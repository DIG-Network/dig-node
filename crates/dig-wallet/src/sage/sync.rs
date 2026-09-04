//! The direct-peer subscription sync (design **Part B**).
//!
//! The primary wallet-data path: connect to Chia full-node peers over the light-wallet
//! protocol on `chia-wallet-sdk` `Peer` (`NodeType::Wallet`, protocol `0.0.37`), subscribe
//! the wallet's puzzle hashes with `request_puzzle_state(subscribe = true)`, then consume
//! `coin_state_update` pushes — persisting every `CoinState` into the local DB
//! ([`crate::sage::db`]) and rolling back on reorg (design B.3). This is byte-parity with
//! `sage-wallet`; it is deliberately NOT built into `chia-query` (that stays the fallback
//! substrate, design C.2).
//!
//! The DB-application + reorg logic is factored into pure async functions
//! ([`apply_coin_states`], [`handle_coin_state_update`]) so it is exercised
//! mainnet-safely against synthetic `CoinState`s AND the Chia peer simulator — no real
//! spends (this PR has none).

use std::collections::HashSet;
use std::time::Duration;

use chia_protocol::Bytes32;
use chia_protocol::{
    Coin, CoinState, CoinStateFilters, CoinStateUpdate, Message, NewPeakWallet,
    ProtocolMessageTypes, RespondPuzzleState,
};
use chia_wallet_sdk::client::Peer;

use super::cat_discovery::{self, DerivedCats};
use super::db::{CatchUpReplay, CoinRow, WalletDb};
use super::events::{EventBus, SyncEvent};
use super::singleton::{self, LineageSource};
#[cfg(doc)]
use super::sync_supervisor::SESSION_MAX_LIFETIME;

/// How long ONE puzzle-state round trip may take before the peer is treated as gone
/// (dig_ecosystem#2851).
///
/// The dial already had a deadline — `sync_supervisor`'s `DIAL_TIMEOUT`, ten seconds — and the
/// request leg simply never got the same treatment. It is not given the same VALUE, because the two
/// are different work: a dial is a handshake, whereas a puzzle-state batch is a real query over a
/// possibly slow link, and one minute is generous for that while still being finite.
///
/// Finite is the whole point. Without it, a peer that goes quiet on a live, ESTABLISHED socket
/// parks the catch-up on a bare `.await` for ever, which is how a supervisor logged "it may now
/// write" and then said nothing at all for two hours.
const PEER_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// A sync error (peer/protocol/db).
#[derive(Debug)]
pub enum SyncError {
    /// A peer client error.
    Peer(String),
    /// The peer rejected a puzzle-state subscription.
    Rejected(String),
    /// A database error.
    Db(sqlx::Error),
    /// A CAT/singleton attribution error (parent-spend read / uncurry).
    Attribution(String),
    /// [`initial_sync_with_authority`] was asked to catch up over an EMPTY puzzle-hash set.
    ///
    /// Refused rather than performed. Subscribing nothing makes a peer answer
    /// `is_finished` on the first response, which would mark the DB
    /// initial-sync-complete over a wallet whose coins were never requested — and
    /// [`crate::sage::routing::route`] then treats that empty DB as authoritative for
    /// every wallet-scoped read. A wallet with no puzzle hashes is not synced; it has
    /// nothing to sync, and those are different states.
    NoPuzzleHashes,
    /// A peer claimed a reorg deeper than [`MAX_REORG_DEPTH`]. Refused, and the session is
    /// dropped rather than the rollback applied (see [`MAX_REORG_DEPTH`]).
    ForkTooDeep {
        /// How many blocks below the current peak the claimed fork point sits.
        depth: u32,
        /// The bound that was exceeded.
        max: u32,
    },
    /// A catch-up was attempted over a peer this node merely DISCOVERED. Refused: only an
    /// operator-chosen peer may make the local replica authoritative (see [`PeerTrust`]).
    UntrustedPeer,
    /// The coin database was RESET while this catch-up was in flight, so everything the
    /// catch-up replayed was discarded before it could finish.
    ///
    /// Refused rather than completed. The reset empties `coins` and clears
    /// `initial_sync_complete` in one transaction, but the catch-up's own writes are separate
    /// transactions that are not serialised against it — so a terminal statement arriving
    /// afterwards would re-declare the emptied (or partially refilled) replica authoritative,
    /// and `routing::route` would answer money reads out of it: `balance 0, synced true` on a
    /// funded wallet, or the likelier understated balance from a partial set.
    ///
    /// The session is dropped and the supervisor runs a fresh catch-up, which is the only thing
    /// that can honestly re-establish the flag.
    ResetDuringCatchUp,
    /// A catch-up ran past [`MAX_CATCH_UP_BATCHES`] without the peer reporting `is_finished`.
    CatchUpTooLong {
        /// The bound that was exceeded.
        max: u32,
    },
    /// A catch-up batch did not advance: the peer answered `is_finished: false` at a height
    /// that did not strictly exceed the previous batch's. Refused, because that is an
    /// unbounded loop rather than progress.
    CatchUpNotAdvancing {
        /// The height the peer repeated (or went back to).
        height: u32,
        /// The height the previous batch already reached.
        previous: u32,
    },
    /// A catch-up tried to write more than [`MAX_CATCH_UP_COINS`] coin states.
    CatchUpTooLarge {
        /// The bound that was exceeded.
        max: usize,
    },
    /// One session walked the replica peak backwards by more than [`MAX_SESSION_ROLLBACK`]
    /// blocks in total, across however many individually-legal frames (see
    /// [`RollbackBudget`]).
    RollbackBudgetExhausted {
        /// The cumulative descent the session had already spent plus this frame's.
        spent: u32,
        /// The bound that was exceeded.
        max: u32,
    },
    /// A writer claimed a peak above the height an independent quorum settled this session
    /// (see [`PeakCeiling`]).
    PeakAboveCeiling {
        /// The height the writer asked the replica to record.
        claimed: u32,
        /// The highest height this session's writer was entitled to claim.
        ceiling: u32,
    },
}

/// How far a peer's word is trusted — the trust boundary this module is built around.
///
/// A peer is not a uniform thing. The `peers` table's `user_managed` rows are addresses an
/// OPERATOR typed in, which is a deliberate act of trust in a specific full node. Everything
/// else arrives by DISCOVERY: a DNS introducer answer, or the `127.0.0.1:8444` probe that any
/// unprivileged co-resident process can answer by binding that port first. Those two are given
/// the same wire protocol and must not be given the same authority.
///
/// # Why a discovered peer can now earn authority (dig_ecosystem#2568)
///
/// Until this change a discovered peer wrote NOTHING — no coins, no `initial_sync_complete`, no
/// peak — and that was correct against the threat but wrong against the product: dig-node is a
/// **light client**, almost nobody runs their own full node, and a default install therefore
/// reached only discovered peers and so never synced at all. `peak_height` stayed NULL forever.
/// The earlier note here called that "the deliberate cost"; a year of it is not a cost, it is
/// the feature not existing.
///
/// The replacement is not "trust discovered peers after all". It is that **a discovered peer's
/// answer becomes authoritative only when a quorum of INDEPENDENTLY and RANDOMLY chosen peers
/// agrees with it** ([`crate::sage::quorum`]), and never on its own. The distinction is the whole
/// design: authority is a property of an ANSWER that survived corroboration, not a property the
/// peer carries into the session.
///
/// # Why the peak is still not the harmless half
///
/// An earlier version let a discovered peer "advance the peak, monotonically", on the reasoning
/// that a too-high peak only makes a confirmation read more conservative. That reasoning was
/// inverted, and the inversion was the vulnerability: a confirmation count is
/// `peak − created_height`, so a HIGHER peak means MORE confirmations, not fewer. One frame at
/// `u32::MAX` therefore reads as ~4.29e9 confirmations for a spend that never landed — and
/// `control.wallet.peak` exists precisely so a caller can bound a claimed confirmation with it.
/// The monotonic rule then made the lie permanent.
///
/// That finding is UNCHANGED and is exactly what corroboration is required to clear. An
/// uncorroborated peer still writes no peak, and [`crate::sage::quorum::eligible`] deliberately
/// anchors its credibility band on the MEDIAN claim so that a `u32::MAX` claimant cannot even
/// shape the candidate set, let alone the replica.
///
/// # Why patching individual leaks was rejected, and still is
///
/// An attacker that empties the replica and then simply closes the socket gets a fresh catch-up
/// on the supervisor's next backoff cycle, and any flag it cleared comes back over whatever it
/// chooses to answer. So the boundary has to be that an uncorroborated peer never reaches the
/// flag at all, which is why [`is_authoritative`](PeerTrust::is_authoritative) is the single
/// question every write site asks, rather than each site re-deriving the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// A `user_managed` row in the `peers` table: an address the operator chose. Full
    /// authority — catch-up, rollback, and the `initial_sync_complete` flag.
    ///
    /// It needs no quorum because the operator already made the trust decision by hand, and
    /// second-guessing an explicit configuration with a vote of strangers would be a strange
    /// inversion of who is in charge.
    Operator,
    /// Found by DNS introducer or the loopback probe, and NOT yet corroborated. Contributes
    /// liveness only, and writes nothing at all.
    ///
    /// This is the state every discovered peer starts in, including one that will be elevated a
    /// moment later: corroboration happens before the catch-up, so there is no window in which an
    /// unproven answer has already landed.
    Discovered,
    /// Found by discovery, and its answer AGREED WITH by a quorum of independently and randomly
    /// chosen other peers at a settled height ([`crate::sage::quorum`]). Full authority, for this
    /// session only.
    ///
    /// "For this session only" is load-bearing. The label is not cached against an address and
    /// not persisted: a peer that corroborated an hour ago is a stranger again on the next
    /// connect, because the thing that was verified was one answer at one height, not the peer's
    /// character. Persisting it would recreate the operator-chosen list the user explicitly
    /// declined to have, with the choosing done by a past round of strangers.
    Corroborated,
}

impl PeerTrust {
    /// Whether this peer's answers may make the local replica authoritative for money.
    ///
    /// The ONE question every write site asks. Adding a variant without deciding this is a
    /// compile error, which is deliberate: the previous audit found the trust rule re-derived
    /// inline at several sites and walked around at one of them.
    pub fn is_authoritative(self) -> bool {
        match self {
            PeerTrust::Operator | PeerTrust::Corroborated => true,
            PeerTrust::Discovered => false,
        }
    }
}

/// The deepest reorg a `coin_state_update` may claim before the session is dropped.
///
/// A rollback is the one destructive operation a peer can drive: `rollback_above(h)` deletes
/// every coin created above `h` and un-spends everything above it, so a single frame claiming
/// `fork_height = 0` erases the entire replica. Chia's consensus makes a deep reorg vanishingly
/// unlikely — a competing chain has to out-weigh the canonical one across the whole span — and a
/// light client cannot validate the claim either way, so the bound has to be a policy rather than
/// a verification. It is set where a real reorg comfortably fits and an erasure does not: 128
/// blocks is roughly 40 minutes of chain at Chia's ~18.75s block time, an order of magnitude
/// beyond any reorg observed on mainnet. A deeper claim is not accepted-and-rolled-back; the
/// session is dropped, the replica is left intact, and the supervisor reconnects — a fresh
/// catch-up is the correct way to resolve a fork we would otherwise be taking on faith.
pub const MAX_REORG_DEPTH: u32 = 128;

/// The cumulative depth ONE session may walk the replica peak backwards, across all frames.
///
/// [`MAX_REORG_DEPTH`] bounds a single frame against the peak *as it stands when that frame
/// arrives* — and an applied rollback lowers the peak, so the next frame's 128 blocks are
/// measured from the new, lower mark. A peer that never exceeds the per-frame bound therefore
/// walks the replica down 128 blocks at a time for as long as it likes; a 40-coin replica was
/// emptied in 31 frames. This bound is measured against the peak the session STARTED from, so
/// the sequence is bounded by the same number the single frame is. Exhausting it drops the
/// session; the supervisor reconnects and a fresh catch-up settles the fork properly.
pub const MAX_SESSION_ROLLBACK: u32 = MAX_REORG_DEPTH;

/// The block interval the peak allowance budgets for — deliberately about HALF Chia's ~18.75s
/// target, so the allowance is a burst headroom rather than a point estimate.
const FAST_BLOCK_SECS: u64 = 9;

/// The over-ceiling `new_peak_wallet` frames one session may send before it is retired.
///
/// The first refusals drop the FRAME only: a single wildly-ahead claim can be a peer mid-reorg or
/// mid-restart, and NC-12 makes corroboration a confidence gradient rather than a ban. Reaching
/// this count is no longer explicable that way, so the session ends and the supervisor redraws a
/// fresh quorum. Nobody is banned; the same peer may be drawn again.
pub const MAX_REFUSED_PEAK_CLAIMS: u32 = 3;

/// Blocks of chain a session may legitimately gain on the height its corroboration round settled.
///
/// Derived from `session_lifetime` rather than hardcoded, because [`SESSION_MAX_LIFETIME`]'s own
/// doc calls its value an overridable operating assumption that may move UP, and a hardcoded
/// ceiling would silently become too tight when it does.
///
/// # Where the two terms come from
///
/// - The anchor is already BEHIND the tip by construction: `quorum::common_height` subtracts
///   `SETTLED_LAG` (2) from the slowest eligible peer, which may itself sit `PEAK_LAG_TOLERANCE`
///   (3) below the best claim — 5 blocks of built-in lag.
/// - Chain progress during a session: 600s at the ~18.75s target is 32 blocks expected;
///   [`FAST_BLOCK_SECS`] yields 66, i.e. 2x burst headroom.
/// - [`MAX_REORG_DEPTH`] is REUSED deliberately, not a new number. It is this crate's existing
///   statement of how far chain state may legitimately move within one session in the OTHER
///   direction ([`MAX_SESSION_ROLLBACK`] is the same value). The bound becomes symmetric: at most
///   128 blocks down cumulatively, at most 128 + elapsed-chain up. Matching an established concept
///   beats inventing a second policy number.
///
/// At the shipped lifetime that totals 194 blocks, about an hour of chain.
pub fn peak_allowance(session_lifetime: Duration) -> u32 {
    MAX_REORG_DEPTH + (session_lifetime.as_secs() / FAST_BLOCK_SECS) as u32
}

/// The highest peak this session's writer may claim.
///
/// `peak_height` is what a caller divides into a CONFIRMATION COUNT, so an unbounded writer can
/// make unconfirmed money read as confirmed — and an inflated peak is effectively permanent,
/// because backwards recovery is capped at [`MAX_SESSION_ROLLBACK`]. Worse, it permanently
/// disables the two liveness guards that would otherwise notice: a saturating "how far behind are
/// we" reads zero for ever, and a stall detector comparing peers against the replica never fires
/// again. So the ceiling is what keeps those guards honest, not merely a second opinion on the
/// peak.
///
/// # Why the anchor is a corroboration round's height
///
/// A quorum-settled height is independent of the writer by construction: elevation requires the
/// writer to AGREE with it, so it is a floor the writer cannot inflate.
///
/// Two alternatives were considered and rejected; the reasons are kept here because they are the
/// reason this shape looks heavier than a one-line delta cap.
///
/// - **A per-frame delta cap** is anchored on the *replica's own* peak, so it cannot distinguish a
///   fresh genesis sync or a three-day-downtime catch-up from an inflation attack. It would need
///   `initial_sync_complete` as a discriminator, and that flag is attacker-clearable —
///   [`handle_coin_state_update`] clears it on any accepted reorg, so a writer that drives one
///   reorg re-opens the very window the bound closes. An absolute anchor needs no discriminator.
/// - **Anchoring on the supervisor's `chia_peer_peak_height`** would import the vulnerability being
///   fixed: it is a monotone MAX over unverified claims, and `quorum::eligible` anchors on the
///   MEDIAN precisely because a max is one-frame-pinnable.
///
/// # It never ratchets
///
/// The ceiling is fixed for the life of the session. Refreshing it is exactly what session
/// rotation already does: every session re-corroborates and gets a new anchor. That is the one
/// place rotation REDUCES exposure rather than raising it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeakCeiling {
    limit: u32,
    anchor: u32,
}

impl PeakCeiling {
    /// The ceiling a session elevated at `anchor` by a corroboration round carries.
    pub fn from_corroborated(anchor: u32, session_lifetime: Duration) -> Self {
        Self {
            limit: anchor.saturating_add(peak_allowance(session_lifetime)),
            anchor,
        }
    }

    /// Whether `claimed` is a height this session's writer is entitled to claim.
    pub fn admits(self, claimed: u32) -> bool {
        claimed <= self.limit
    }

    /// The highest claimable height.
    pub fn limit(self) -> u32 {
        self.limit
    }

    /// The quorum-settled height the ceiling was built on.
    pub fn anchor(self) -> u32 {
        self.anchor
    }
}

/// What a session is entitled to write — [`PeerTrust`] plus, for the elevated-stranger tier, the
/// ceiling that tier is only ever granted WITH.
///
/// `Corroborated` cannot be constructed without a [`PeakCeiling`], and that is the whole point:
/// the previous shape carried a bare trust label, so "elevated but unbounded" was a representable
/// state one refactor could reintroduce. [`PeerTrust`] stays the wire-facing enum that
/// [`PeerTrust::is_authoritative`] answers for; `WriteAuthority` is what SESSIONS carry.
///
/// `Operator` is deliberately unbounded: the operator hand-configured that address, corroboration
/// only runs on the discovery path so no independent anchor exists for such a session, and
/// inventing one would second-guess an explicit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAuthority {
    /// An operator-chosen peer. Full authority, no ceiling.
    Operator,
    /// A discovered peer a quorum agreed with, bounded by the height that quorum settled.
    Corroborated(PeakCeiling),
    /// A discovered peer. Writes nothing.
    Discovered,
}

impl WriteAuthority {
    /// The trust tier this authority carries.
    pub fn trust(self) -> PeerTrust {
        match self {
            WriteAuthority::Operator => PeerTrust::Operator,
            WriteAuthority::Corroborated(_) => PeerTrust::Corroborated,
            WriteAuthority::Discovered => PeerTrust::Discovered,
        }
    }

    /// The ceiling every peak claim of this session is checked against, if it has one.
    pub fn ceiling(self) -> Option<PeakCeiling> {
        match self {
            WriteAuthority::Corroborated(ceiling) => Some(ceiling),
            WriteAuthority::Operator | WriteAuthority::Discovered => None,
        }
    }
}

/// The most catch-up round trips one [`initial_sync_with_authority`] may make.
///
/// The loop continues while the peer answers `is_finished: false`, and the peer chooses that
/// bit. Combined with the strict height-monotonicity check below this is belt and braces: the
/// height check alone bounds the loop by the chain's length, which is millions. A real
/// catch-up needs a handful of batches even for a heavily-used wallet.
pub const MAX_CATCH_UP_BATCHES: u32 = 1_024;

/// The most coin states one [`initial_sync_with_authority`] may write, summed across its batches.
///
/// A peer answering a subscription decides how many rows it hands back and can repeat them
/// with fresh coin ids forever; without this, `wallet.sqlite` grows for as long as the peer
/// keeps talking. Set well above any real wallet's lifetime coin count and well below a disk
/// problem.
pub const MAX_CATCH_UP_COINS: usize = 250_000;

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Peer(e) => write!(f, "peer: {e}"),
            SyncError::Rejected(e) => write!(f, "subscription rejected: {e}"),
            SyncError::Db(e) => write!(f, "db: {e}"),
            SyncError::Attribution(e) => write!(f, "attribution: {e}"),
            SyncError::NoPuzzleHashes => write!(
                f,
                "refusing to catch up over an empty puzzle-hash set (nothing to subscribe)"
            ),
            SyncError::ForkTooDeep { depth, max } => write!(
                f,
                "peer claimed a reorg {depth} blocks deep (bound {max}); dropping the session \
                 rather than rolling the replica back"
            ),
            SyncError::UntrustedPeer => write!(
                f,
                "refusing to catch up over a discovered peer (only an operator-chosen peer may \
                 make the local replica authoritative)"
            ),
            SyncError::ResetDuringCatchUp => write!(
                f,
                concat!(
                    "the coin database was reset while this catch-up was in flight; its ",
                    "result was discarded rather than used to mark the emptied replica synced"
                )
            ),
            SyncError::CatchUpTooLong { max } => {
                write!(f, "catch-up exceeded {max} batches without finishing")
            }
            SyncError::CatchUpNotAdvancing { height, previous } => write!(
                f,
                "catch-up batch reported height {height} after {previous}; a batch must \
                 strictly advance"
            ),
            SyncError::CatchUpTooLarge { max } => {
                write!(f, "catch-up exceeded {max} coin states")
            }
            SyncError::RollbackBudgetExhausted { spent, max } => write!(
                f,
                "session walked the replica peak back {spent} blocks in total (bound {max}); \
                 dropping the session"
            ),
            SyncError::PeakAboveCeiling { claimed, ceiling } => write!(
                f,
                "a writer claimed a peak of {claimed} above the height an independent quorum \
                 settled this session (ceiling {ceiling}); dropping the session"
            ),
        }
    }
}
impl std::error::Error for SyncError {}
impl From<sqlx::Error> for SyncError {
    fn from(e: sqlx::Error) -> Self {
        SyncError::Db(e)
    }
}

/// Map a Chia `CoinState` to a wallet DB [`CoinRow`]. A raw `CoinState` does not reveal
/// whether a coin is a CAT (that lives in its parent's spend), so this stores `asset_id`
/// as `None`; a [`CatAttributor`] pass (design B.6, #407) then uncurries the parent spend
/// via [`singleton::reconstruct_coins`] and fills in the CAT `asset_id`/`hint`, so
/// `get_cats`/`$DIG` resolve. XCH coins legitimately keep `asset_id: None`.
pub fn coin_state_to_row(state: &CoinState) -> CoinRow {
    let coin: &Coin = &state.coin;
    CoinRow {
        coin_id: hex::encode(coin.coin_id()),
        parent_coin_info: hex::encode(coin.parent_coin_info),
        puzzle_hash: hex::encode(coin.puzzle_hash),
        amount: coin.amount.to_string(),
        created_height: state.created_height.map(i64::from),
        spent_height: state.spent_height.map(i64::from),
        asset_id: None,
        hint: None,
        created_timestamp: None,
        spent_timestamp: None,
    }
}

/// The puzzle hashes a session actually subscribed — the only coins it is entitled to write.
///
/// A peer answers a subscription; it does not get to define one. `request_puzzle_state` hands the
/// peer an explicit hash set, and every `CoinState` it pushes back is checked against that set
/// here, because the socket is untrusted (a co-resident process that binds `127.0.0.1:8444` is
/// the node's chain source on the very next connect) and an unfiltered upsert lets it invent
/// coins at hashes the wallet never asked about.
///
/// It is deliberately NOT the whole defence: nothing here can stop a peer lying about coins the
/// wallet *does* own. That is what [`handle_coin_state_update`]'s fail-closed latch is for.
pub type SubscribedHashes = HashSet<Bytes32>;

/// The empty derived-CAT set, for a session that follows none.
///
/// A shared `'static` so [`SessionState`] can hold a plain borrow rather than an `Option`, which
/// keeps every read of the field a single lookup with no "derives nothing" branch to forget.
fn no_derived_cats() -> &'static DerivedCats {
    static NONE: std::sync::OnceLock<DerivedCats> = std::sync::OnceLock::new();
    NONE.get_or_init(DerivedCats::default)
}

/// Everything one peer session carries across the frames it handles: what it subscribed, how
/// far its peer is trusted, and how much of its rollback allowance it has spent.
///
/// It exists because two of this module's defences are per-SESSION rather than per-frame — the
/// trust boundary ([`PeerTrust`]) and the cumulative rollback bound ([`RollbackBudget`]) — and a
/// free function handed one frame at a time cannot enforce either. [`run_update_loop`] owns one
/// and lends it to every [`handle_coin_state_update`] call.
pub struct SessionState<'a> {
    /// The puzzle hashes this session subscribed. Empty when the session subscribes nothing.
    ///
    /// **The wallet's own p2 hashes only** — never the derived CAT outer hashes below. Two
    /// consumers read this field expecting *addresses*: the `coins` admission filter, and
    /// `record_arrivals`, which turns it into "you were paid" notifications. Widening it to
    /// include outer CAT hashes is exactly the defect that produced a false payment notice
    /// earlier in this ticket family, so the two sets stay separate fields rather than one union.
    pub subscribed: &'a SubscribedHashes,
    /// The outer CAT puzzle hashes this session ALSO subscribed, with the derivation that produced
    /// each. Coins arriving at these are STAGED, never admitted — see
    /// [`crate::sage::cat_discovery`].
    pub derived: &'a DerivedCats,
    /// What this session's peer is entitled to write, and up to what height.
    pub authority: WriteAuthority,
    /// The session's remaining allowance for walking the peak backwards.
    pub rollback: RollbackBudget,
    /// How many peak claims above the ceiling this session has already had refused.
    pub refused_peaks: u32,
}

impl<'a> SessionState<'a> {
    /// A session over `subscribed` entitled to write exactly what `authority` says.
    pub fn with_authority(subscribed: &'a SubscribedHashes, authority: WriteAuthority) -> Self {
        Self {
            subscribed,
            derived: no_derived_cats(),
            authority,
            rollback: RollbackBudget::new(),
            refused_peaks: 0,
        }
    }

    /// Also follow `derived`, the outer CAT hashes this session subscribed (dig-node#380).
    ///
    /// Chained rather than added to [`Self::with_authority`] so that a session which derives
    /// nothing — a node with no known CAT assets, or a locked wallet — keeps the exact shape it
    /// has on `main`, and so that every existing caller states its intent by its absence.
    #[must_use]
    pub fn following_derived_cats(mut self, derived: &'a DerivedCats) -> Self {
        self.derived = derived;
        self
    }

    /// Check `claimed` against this session's [`PeakCeiling`], charging a strike if it is refused.
    ///
    /// THE ONE PLACE a live peer frame's height is judged. Both frame types that carry a peak
    /// ([`handle_coin_state_update`] and the `new_peak_wallet` arm of [`run_update_loop`]) route
    /// through here, and neither can write a peak without the [`AdmittedPeak`] it returns.
    ///
    /// The third peak-carrying write, a catch-up terminal, is guarded by
    /// [`CatchUpReplay::finished_at`] instead and deliberately not by this: that value arms
    /// `initial_sync_complete` and the arrival baseline in the same statement, so it gets none of
    /// the three-strike tolerance below — there is no benign reading of it.
    ///
    /// # Why refusals are tolerated before they are fatal
    ///
    /// A single wildly-ahead claim can be a peer mid-reorg or mid-restart, and NC-12 makes
    /// corroboration a confidence gradient rather than a ban. Reaching
    /// [`MAX_REFUSED_PEAK_CLAIMS`] is no longer explicable that way, so the session ends and the
    /// supervisor redraws a fresh quorum. Nobody is banned; the same peer may be drawn again.
    pub fn admit_peak(&mut self, claimed: u32) -> Result<PeakClaim, SyncError> {
        let Some(ceiling) = self.authority.ceiling() else {
            return Ok(PeakClaim::Admitted(AdmittedPeak { height: claimed }));
        };
        if ceiling.admits(claimed) {
            return Ok(PeakClaim::Admitted(AdmittedPeak { height: claimed }));
        }
        tracing::warn!(
            claimed,
            ceiling = ceiling.limit(),
            anchor = ceiling.anchor(),
            trust = ?self.authority.trust(),
            "wallet sync: refusing a peak above the session's corroborated ceiling"
        );
        self.refused_peaks = self.refused_peaks.saturating_add(1);
        if self.refused_peaks >= MAX_REFUSED_PEAK_CLAIMS {
            tracing::warn!(
                refused = self.refused_peaks,
                "wallet sync: retiring the session after repeated over-ceiling peak claims; a \
                 fresh quorum will be redrawn"
            );
            return Err(SyncError::PeakAboveCeiling {
                claimed,
                ceiling: ceiling.limit(),
            });
        }
        Ok(PeakClaim::Refused)
    }
}

/// A peak height the session's [`WriteAuthority`] has already been checked against.
///
/// [`WalletDb::record_peak`] takes one of these and [`SessionState::admit_peak`] is the only thing
/// that builds one, so "write a peak without consulting the ceiling" is not a state production code
/// can express — the same trick [`CatchUpReplay`] plays for the routing gate.
///
/// This shape exists because the ENUMERATION is what failed once already (dig_ecosystem#2851): the
/// bound was written as a check repeated at each known write site, the set was believed to be two,
/// and the third site — [`handle_coin_state_update`] — silenced both liveness guards through a
/// frame nobody had enumerated. A checked value cannot be forgotten by the next site added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedPeak {
    height: u32,
}

impl AdmittedPeak {
    /// The admitted height.
    pub fn height(self) -> u32 {
        self.height
    }
}

/// What [`SessionState::admit_peak`] concluded about one claimed height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused peak claim means the FRAME must be dropped, not merely not written"]
pub enum PeakClaim {
    /// The claim is within this session's authority; write it.
    Admitted(AdmittedPeak),
    /// The claim was above the ceiling and a strike was charged. Drop the frame, keep the session.
    Refused,
}

/// The cumulative descent one session is allowed to drive, bounded by [`MAX_SESSION_ROLLBACK`].
///
/// See that constant for why a per-frame bound is not enough on its own.
#[derive(Debug, Default)]
pub struct RollbackBudget {
    spent: u32,
}

impl RollbackBudget {
    /// A fresh, unspent budget.
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge `depth` blocks of descent, or refuse if that would exceed the bound.
    ///
    /// Refusing leaves the budget unchanged, so the error is about the frame that asked for
    /// too much rather than about the session becoming permanently poisoned by it — the caller
    /// drops the session either way.
    pub fn charge(&mut self, depth: u32) -> Result<(), SyncError> {
        let spent = self.spent.saturating_add(depth);
        if spent > MAX_SESSION_ROLLBACK {
            return Err(SyncError::RollbackBudgetExhausted {
                spent,
                max: MAX_SESSION_ROLLBACK,
            });
        }
        self.spent = spent;
        Ok(())
    }
}

impl CatchUpReplay {
    /// The replay that ended at `peak_height` / `header_hash` — the terminal `is_finished`
    /// puzzle-state response's own values, never a height borrowed from somewhere else — or
    /// [`SyncError::PeakAboveCeiling`] when `ceiling` does not admit that height.
    ///
    /// The check belongs on the CONSTRUCTOR rather than in [`WalletDb::complete_catch_up`],
    /// extending the trick that already protects that call: the value is hard to construct, so a
    /// caller with nothing legitimate to build one out of cannot arm the flag by accident.
    ///
    /// A refusal here ends the session immediately, with none of the three-strike tolerance the
    /// stray `new_peak_wallet` frame gets. Unlike a peak frame, this value arms
    /// `initial_sync_complete` AND the arrival baseline in the same statement, so there is no
    /// benign reading of it.
    /// `covered` is the puzzle-hash set the catch-up SUBSCRIBED — the same vector the request
    /// loop sent — and it is a required argument for the same reason the header hash is: the
    /// completion write records which addresses it covered, and a set passed alongside the write
    /// rather than carried by the evidence could describe a different one (dig_ecosystem#2871).
    pub fn finished_at(
        ceiling: Option<PeakCeiling>,
        peak_height: u32,
        header_hash: impl Into<String>,
        covered: &[Bytes32],
    ) -> Result<Self, SyncError> {
        if let Some(ceiling) = ceiling {
            if !ceiling.admits(peak_height) {
                tracing::warn!(
                    claimed = peak_height,
                    ceiling = ceiling.limit(),
                    anchor = ceiling.anchor(),
                    "wallet sync: refusing a catch-up terminal above the session's corroborated \
                     ceiling; retiring the session so a fresh quorum is redrawn"
                );
                return Err(SyncError::PeakAboveCeiling {
                    claimed: peak_height,
                    ceiling: ceiling.limit(),
                });
            }
        }
        Ok(Self {
            peak_height,
            header_hash: header_hash.into(),
            covered: crate::sage::coverage::CoveredSet::from_hashes(covered),
        })
    }
}

/// The running cost of one catch-up, bounded by [`MAX_CATCH_UP_BATCHES`] and
/// [`MAX_CATCH_UP_COINS`].
///
/// Split out of [`initial_sync_with_authority`] as a small value with no I/O so both bounds can be pinned
/// from ABOVE and BELOW in a unit test — a cap tested only from one side confirms only itself,
/// and driving 250,000 rows through SQLite to prove the at-bound case would be a test nobody
/// runs.
#[derive(Debug, Default)]
pub struct CatchUpBudget {
    batches: u32,
    coins: usize,
}

impl CatchUpBudget {
    /// A fresh, unspent budget.
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge one batch carrying `coin_states` rows, or refuse if either bound is exceeded.
    ///
    /// Charged BEFORE the rows are written, so a batch that busts the bound never reaches the
    /// database.
    pub fn charge(&mut self, coin_states: usize) -> Result<(), SyncError> {
        self.batches = self.batches.saturating_add(1);
        if self.batches > MAX_CATCH_UP_BATCHES {
            return Err(SyncError::CatchUpTooLong {
                max: MAX_CATCH_UP_BATCHES,
            });
        }
        self.coins = self.coins.saturating_add(coin_states);
        if self.coins > MAX_CATCH_UP_COINS {
            return Err(SyncError::CatchUpTooLarge {
                max: MAX_CATCH_UP_COINS,
            });
        }
        Ok(())
    }
}

/// Apply a batch of `CoinState`s into the DB (the core of `coin_state_update`). Each state
/// is upserted by coin id, so a later spend overwrites the earlier unspent row.
///
/// Coins at a puzzle hash outside `subscribed` are dropped — they were never requested, so a
/// peer offering them is either confused or hostile, and either way the replica must not grow a
/// row the wallet cannot account for.
///
/// # This function ROUTES; it never TYPES (dig-node#380)
///
/// Three destinations, decided purely by which locally-derived set a coin's puzzle hash is in:
///
/// - **`subscribed`** — the wallet's own p2 hashes. Straight into `coins`, exactly as on `main`.
/// - **`derived`** — an outer CAT hash this wallet computed for a known asset. The coin is
///   **staged**, not admitted: sitting at that hash is a claim anybody could have made
///   ([`crate::sage::cat_discovery`] carries the full argument), and belief costs a lineage proof
///   that this function deliberately cannot perform.
/// - **neither** — dropped and warned about, as before.
///
/// A derived-hash coin that has ALREADY been promoted is the one exception: it is a believed coin
/// now, so its later states — its spend above all — update `coins` normally. Without that, a
/// promoted coin would remain unspent in the replica forever and be re-selected after it was spent.
///
/// **Zero chain reads**, structurally: every decision here is a hash-set membership test against
/// values derived locally, and the staging path takes no lineage source to read through.
pub async fn apply_coin_states(
    db: &WalletDb,
    states: &[CoinState],
    subscribed: &SubscribedHashes,
    derived: &DerivedCats,
) -> Result<(), SyncError> {
    // A derived-hash coin already in `coins` has cleared promotion; asked once for the whole
    // batch rather than per coin.
    let derived_ids: Vec<String> = states
        .iter()
        .filter(|s| derived.owner_of(&s.coin.puzzle_hash).is_some())
        .map(|s| hex::encode(s.coin.coin_id()))
        .collect();
    let promoted = db.existing_coin_ids(&derived_ids).await?;

    let rows: Vec<CoinRow> = states
        .iter()
        .filter(|s| {
            subscribed.contains(&s.coin.puzzle_hash)
                || (derived.owner_of(&s.coin.puzzle_hash).is_some()
                    && promoted.contains(&hex::encode(s.coin.coin_id())))
        })
        .map(coin_state_to_row)
        .collect();
    let staged = cat_discovery::stage_from_states(states, derived, |id| promoted.contains(id));
    let accounted = rows.len() + staged.len();
    if accounted != states.len() {
        tracing::warn!(
            dropped = states.len() - accounted,
            "wallet sync: peer pushed coin states outside the subscribed puzzle-hash set"
        );
    }
    db.upsert_coins(&rows).await?;
    if !staged.is_empty() {
        db.stage_cat_admissions(&staged).await?;
    }
    Ok(())
}

/// The CAT/singleton attribution step of the sync loop (design B.6, #407). Coins arrive
/// from `coin_state_update` with `asset_id: None` (a raw `CoinState` does not reveal the
/// asset); this uncurries each candidate coin's parent spend through `lineage` and fills in
/// the CAT `asset_id`/`hint` (and NFT/DID rows), so `get_cats`/`get_token` are complete.
///
/// `plain_puzzle_hashes` are the wallet's own p2 hashes — a coin sitting at one of them
/// with an even amount is an ordinary XCH coin and is skipped (never fetches a parent
/// spend). Attribution reads only; it never signs or broadcasts.
pub struct CatAttributor<'a> {
    /// The parent-spend source (coinset/peer point-read) the whole-replica pass reads through.
    ///
    /// ONE source, unmetered, and deliberately so: this pass runs on the node's own schedule over
    /// rows the replica already holds, so its volume is set by what has newly arrived rather than
    /// by anything a remote peer chooses to send.
    pub lineage: &'a dyn LineageSource,
    /// The address bech32m prefix for any reconstructed NFT/DID addresses.
    pub prefix: &'a str,
    /// The wallet's own plain p2 puzzle hashes (hex) — ordinary XCH coins at these are skipped.
    pub plain_puzzle_hashes: &'a HashSet<String>,
}

impl CatAttributor<'_> {
    /// Attribute every not-yet-attributed coin currently in `db` (idempotent: already-spent
    /// or already-attributed coins are skipped by [`singleton::reconstruct_coins`]).
    ///
    /// Runs the CAT admission PROMOTION pass first (dig-node#380), so a coin discovered at a
    /// derived hash becomes a believed coin in the same out-of-band pass that attributes the rest.
    pub async fn attribute(&self, db: &WalletDb) -> Result<(), SyncError> {
        self.promote(db).await;
        singleton::reconstruct_all(db, self.lineage, self.prefix, self.plain_puzzle_hashes)
            .await
            .map(|_| ())
            .map_err(|e| SyncError::Attribution(e.to_string()))
    }

    /// Promote whatever the staging table can prove, and SWALLOW every failure.
    ///
    /// Returning nothing is the point, not an oversight. [`run_update_loop`] calls
    /// `attribute(db).await?` on the peer frame path, so any error this pass could produce would
    /// propagate out of the update loop and END A LIVE SESSION. Promotion reads the chain, and a
    /// chain read fails for reasons a peer can arrange — which would hand that peer a denial
    /// primitive, the precise defect that earlier rounds of this work introduced twice.
    ///
    /// A swallowed failure costs a delay and nothing else: the staged rows are untouched, so the
    /// next pass retries them. Absent, never wrong.
    async fn promote(&self, db: &WalletDb) {
        match cat_discovery::promote_staged_cats(db, self.lineage, self.plain_puzzle_hashes).await {
            Ok(stats) if stats.promoted > 0 || stats.refused > 0 => {
                tracing::info!(
                    promoted = stats.promoted,
                    refused = stats.refused,
                    deferred = stats.deferred,
                    "wallet sync: CAT admission promotion pass"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "wallet sync: CAT admission promotion failed; the staged coins are retried \
                     on the next pass"
                );
            }
        }
    }
}

/// Drain `arrival_pending`/newly-confirmed coins into `arrivals` for `session`, through
/// `through_height` — logging a failure rather than propagating it.
///
/// # Two call sites in one frame (dig-node#546)
///
/// [`handle_coin_state_update`] calls this once, right after a frame's coin writes land — but a
/// CAT staged in THIS SAME frame is not in `coins` yet at that point; it is only promoted
/// afterwards, when [`run_update_loop`] runs the [`CatAttributor`] pass. That ordering is
/// #479/#480's own fix (a coin must be judged news-or-history at the moment it is first STAGED,
/// never re-asked after the watermark has moved onto its own height), so it cannot simply be
/// reversed. Its corollary is the hold `promote_cat_admission` leaves in `arrival_pending`:
/// nothing examines that hold until this function runs again, and without a second call in the
/// SAME frame, that only ever happened on the NEXT `coin_state_update` — which a wallet that
/// receives once and then falls quiet may never get. [`run_update_loop`] calls this a second
/// time, right after attribution, to close that gap at its source rather than trust a frame that
/// may never arrive to close it.
///
/// # Safe to call twice, unconditionally
///
/// [`WalletDb::record_arrivals`] is idempotent — an already-recorded coin id is `INSERT OR
/// IGNORE`d, and its baseline only ever advances (`MAX`) — so a second call at the same height
/// re-examines rather than re-announces: it changes nothing the first call already settled, and
/// only newly catches what attribution just promoted.
///
/// # Why a failure here is logged, not propagated
///
/// Chain sync is the critical path and a notification ledger is not: returning an error would
/// drop a live peer session over a NOTIFICATION write, which is a strictly worse outcome than a
/// delayed toast. Nothing is lost by continuing — the ledger insert and the baseline advance
/// share one transaction, so a failed pass leaves the watermark where it was and the next call
/// (the next frame's, if not this frame's own second one) re-examines the same coins.
async fn record_arrivals_or_log(db: &WalletDb, session: &SessionState<'_>, through_height: u32) {
    let watched: Vec<String> = session.subscribed.iter().map(hex::encode).collect();
    if let Err(e) = db.record_arrivals(&watched, through_height).await {
        tracing::warn!(
            error = %e,
            height = through_height,
            "wallet sync: recording incoming-funds arrivals failed; retrying on the next update"
        );
    }
}

/// Handle a `coin_state_update` push: on a reorg (`fork_height` below the current peak)
/// roll the DB back above the fork first (design B.3), then apply the update's coin states
/// and advance the synced peak. Publishes [`SyncEvent::CoinState`] on `events` once applied
/// (design A.9) — a best-effort push notification; `get_sync_status` polling stays the
/// authoritative source of truth regardless of whether anything is subscribed to `events`.
///
/// # Fail closed on any backwards move
///
/// A rollback, or a peak that moves backwards, means the replica no longer holds the state a
/// completed catch-up established. The routing gate
/// ([`crate::sage::db::WalletDb::is_synced`] → [`crate::sage::routing::route`]) is what makes an
/// emptied DB *authoritative*, so a destructive push must clear it: the wallet then reads from
/// the fallback tier until a genuine catch-up re-establishes the flag. Without this, one hostile
/// frame makes a funded wallet answer `balance 0, synced true`.
///
/// An earlier version of this note called that state *permanent*, "because nothing else ever
/// re-runs the catch-up while the connection survives". That was wrong, and wrong in the
/// direction that matters: the ATTACKER chooses when the connection survives. Closing the socket
/// costs it one backoff cycle and buys a fresh catch-up, over which it answers whatever it likes.
/// Un-latching here is therefore necessary and was never sufficient; what makes it sufficient is
/// that only an operator-chosen peer can re-latch at all ([`PeerTrust`]).
///
/// The cost of being conservative here is a temporary fallback read after a *legitimate* reorg,
/// which is correct: after a rollback the replica genuinely is behind.
///
/// # A discovered peer's frame is dropped whole
///
/// When `session.authority` is [`PeerTrust::Discovered`] this returns without touching the database:
/// no rollback, no coin write, no routing flag, and no peak (see [`PeerTrust`] for why the peak
/// is not the harmless half). Dropping the frame is not an error — the session stays up, because
/// the peer still counts toward `subscription_peer_count`.
pub async fn handle_coin_state_update(
    db: &WalletDb,
    update: &CoinStateUpdate,
    events: &EventBus,
    session: &mut SessionState<'_>,
) -> Result<FrameApplied, SyncError> {
    if !session.authority.trust().is_authoritative() {
        tracing::debug!(
            claimed_height = update.height,
            "wallet sync: dropping a coin_state_update from a discovered peer"
        );
        return Ok(FrameApplied::Dropped);
    }
    // Judged BEFORE the frame acts, not at the write. A guard sitting on the `set_peak` call would
    // satisfy "the peak is unchanged" identically while the rollback below had already deleted
    // coins and cleared the routing gate on the strength of a height about to be rejected. A frame
    // whose height is a lie is suspect in its entirety, so a refusal drops the whole frame — its
    // coins included, which is also the conservative reading of coins offered alongside one.
    let admitted = match session.admit_peak(update.height)? {
        PeakClaim::Admitted(peak) => peak,
        PeakClaim::Refused => return Ok(FrameApplied::Dropped),
    };
    let current_peak = db.sync_state().await?.peak_height;
    let mut moved_backwards = false;
    if let Some(peak) = current_peak {
        if update.fork_height < peak {
            let depth = peak - update.fork_height;
            if depth > MAX_REORG_DEPTH {
                return Err(SyncError::ForkTooDeep {
                    depth,
                    max: MAX_REORG_DEPTH,
                });
            }
            session.rollback.charge(depth)?;
            db.rollback_above(update.fork_height).await?;
            moved_backwards = true;
        }
        moved_backwards |= update.height < peak;
    }
    if moved_backwards {
        tracing::warn!(
            fork_height = update.fork_height,
            height = update.height,
            previous_peak = ?current_peak,
            "wallet sync: replica moved backwards; clearing initial-sync-complete so wallet \
             reads fall back until a fresh catch-up"
        );
        db.clear_initial_sync_complete().await?;
    }
    apply_coin_states(db, &update.items, session.subscribed, session.derived).await?;
    db.record_peak(admitted, &hex::encode(update.peak_hash))
        .await?;
    // Incoming-funds arrivals (dig_ecosystem#2548), recorded AFTER the batch has committed and
    // the peak has advanced — never during the write. A parent and its change coin arrive in the
    // same frame in whatever order the peer chose, so deciding "did we create this coin ourselves?"
    // inside the write would race the batch and read the user's own change as a payment.
    //
    // The recorder is fail-closed on its own: with no baseline (no completed catch-up) it records
    // nothing, so the history this same function replays on every reconnect is never announced.
    //
    // This is the FIRST of this frame's two drain attempts — see [`record_arrivals_or_log`] for
    // why a second one runs later, after attribution (dig-node#546).
    record_arrivals_or_log(db, session, update.height).await;
    events.publish(SyncEvent::CoinState);
    Ok(FrameApplied::Applied)
}

/// Whether a `coin_state_update` frame reached the database at all.
///
/// Returned so the caller can decide whether the follow-up attribution pass is worth running. A
/// frame dropped for coming from a discovered peer, or for claiming a peak this session will not
/// admit, changed nothing — so a pass after it can only re-examine rows an earlier pass already
/// settled. Without the distinction, an *empty, refused* frame from an untrusted peer still buys a
/// whole-replica scan and a chain read per candidate row, which is roughly forty bytes on the wire
/// for an unbounded amount of this node's work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameApplied {
    /// The frame's coins and peak were written.
    Applied,
    /// The frame was refused before any database write.
    Dropped,
}

/// The one peer call [`initial_sync_with_authority`] makes, behind a trait.
///
/// `chia_wallet_sdk::client::Peer` can only exist on top of a live socket, so the catch-up
/// loop — including the empty-set refusal that protects `initial_sync_complete` — would
/// otherwise be unreachable from a test. The trait is deliberately the narrowest possible
/// surface: one request, the same arguments the protocol takes.
#[async_trait::async_trait]
pub trait PuzzleStateSource: Sync {
    /// Request (and subscribe) puzzle state from `header_hash` forward.
    async fn request_puzzle_state(
        &self,
        puzzle_hashes: Vec<Bytes32>,
        previous_height: Option<u32>,
        header_hash: Bytes32,
    ) -> Result<RespondPuzzleState, SyncError>;
}

#[async_trait::async_trait]
impl PuzzleStateSource for Peer {
    async fn request_puzzle_state(
        &self,
        puzzle_hashes: Vec<Bytes32>,
        previous_height: Option<u32>,
        header_hash: Bytes32,
    ) -> Result<RespondPuzzleState, SyncError> {
        match Peer::request_puzzle_state(
            self,
            puzzle_hashes,
            previous_height,
            header_hash,
            CoinStateFilters::new(true, true, true, 0),
            true,
        )
        .await
        .map_err(|e| SyncError::Peer(e.to_string()))?
        {
            Ok(r) => Ok(r),
            Err(reject) => Err(SyncError::Rejected(format!("{reject:?}"))),
        }
    }
}

/// The catch-up itself, for a session that already knows what it is entitled to write.
///
/// This is where the terminal height meets the session's [`PeakCeiling`] — see
/// [`CatchUpReplay::finished_at`], which refuses an over-ceiling terminal rather than arming
/// `initial_sync_complete` over it.
/// # The two sets are NOT one set (dig-node#394)
///
/// A catch-up needs COVERAGE over addresses AND derived CAT hashes -- the peer must be asked about
/// both, or a discovered CAT coin is never seen at all. It needs ADMISSION over addresses only:
/// a coin at a derived hash is a claim anybody could have made, and admitting it writes a coin the
/// schema types `asset_id: None`, which means XCH, into the money table.
///
/// Those are different sets, and an earlier round of this work passed ONE vector serving both
/// roles. That is why the union is performed HERE and cannot be performed by a caller: `addresses`
/// is the admission set, `derived` is the widening, and `requested` -- the union -- exists only
/// inside this function and only reaches the peer request. A caller that wanted to widen admission
/// would have to hand a derived hash in `addresses`, and the `subscribed` construction below
/// FILTERS those out, so even that does not work. One admission point, structurally unwidenable.
#[allow(clippy::too_many_arguments)]
pub async fn initial_sync_with_authority(
    peer: &dyn PuzzleStateSource,
    db: &WalletDb,
    addresses: Vec<Bytes32>,
    genesis_challenge: Bytes32,
    peer_ip: &str,
    events: &EventBus,
    authority: WriteAuthority,
    derived: &DerivedCats,
) -> Result<(), SyncError> {
    let trust = authority.trust();
    // THE TRUST BOUNDARY. This is the only place a PEER can set `initial_sync_complete`, and
    // that flag is what `routing::route` turns into "the local replica answers for money". So
    // the check belongs HERE, at the floor, rather than only in
    // the supervisor that decides which peer to dial: a supervisor-side check is one refactor —
    // or one reconnect after a hostile disconnect — away from gone, which is precisely how the
    // previous, per-leak version of this defence was walked around.
    //
    // "Only place a PEER can set it" is precise, not loose: [`crate::sage::rpc::WalletBackend::
    // refresh_tracked_coins`] also latches the flag, from the coinset ORACLE tier. That path
    // takes no peer input, so it is outside this boundary — but it is not outside notice, and
    // its own doc records the empty-fallback case it latches over.
    if !trust.is_authoritative() {
        return Err(SyncError::UntrustedPeer);
    }

    // THE INVARIANT. An empty subscription is answered `is_finished` at once, and the
    // completion flag below would then declare an un-queried DB authoritative for every
    // wallet-scoped read (`routing::route(true, true) == Source::Db`). The guard lives HERE,
    // at the floor, and not only in the supervisor that calls it: a caller-side check is one
    // refactor away from gone, and this function is the only thing that can set the flag.
    if addresses.is_empty() {
        return Err(SyncError::NoPuzzleHashes);
    }

    // ADMISSION. Addresses only, and derived hashes actively removed rather than merely not added:
    // this set decides what enters `coins`, and `coins` is the money table. The filter is what
    // makes the guarantee structural instead of a convention every caller has to remember.
    let subscribed: SubscribedHashes = addresses
        .iter()
        .copied()
        .filter(|h| derived.owner_of(h).is_none())
        .collect();
    if subscribed.len() != addresses.len() {
        tracing::warn!(
            removed = addresses.len() - subscribed.len(),
            "wallet sync: a derived CAT hash was offered as an address; refused admission"
        );
    }

    // COVERAGE. The union, built here and used for nothing but the peer request. A coin arriving
    // at a derived hash is routed to staging by `apply_coin_states`, never to `coins`.
    let requested: Vec<Bytes32> = {
        let mut all = addresses.clone();
        all.extend(derived.hashes());
        all.sort();
        all.dedup();
        all
    };
    // Observed before this catch-up's FIRST WRITE and presented again in its terminal
    // statement, so a reset landing at any point during the replay moves the counter away
    // from this value and the completion cannot land (dig-node#454). Reading it at the END
    // would defeat the guard entirely: the value would already include the reset.
    //
    // Taken lazily, at the first write rather than before the first REQUEST, for two
    // reasons. It is equally sound — nothing has been written yet either way, so a reset
    // that lands before this point leaves a replay that runs wholly after it, which is
    // exactly the catch-up entitled to re-establish the flag. And it keeps this function
    // free of database work before its first peer round trip, where the only armed timer
    // is a caller's outer bound.
    let mut epoch_at_first_write: Option<crate::sage::db::ResetEpoch> = None;
    let mut previous_height: Option<u32> = None;
    let mut header_hash = genesis_challenge;
    events.publish(SyncEvent::Start {
        ip: peer_ip.to_string(),
    });

    let mut first_batch = true;
    let mut budget = CatchUpBudget::new();
    loop {
        // Bounded per ROUND TRIP, never over the catch-up as a whole (dig_ecosystem#2851). A first
        // catch-up runs from genesis over many batches and legitimately takes a long time, so a
        // total deadline would kill a healthy long sync — a worse failure than the one being fixed.
        // A single request/response has no such excuse: a peer that has not answered one batch in
        // a minute has gone quiet, and without a deadline here this `.await` parks the whole
        // supervisor for the life of the process on a socket that stays ESTABLISHED. A supervisor
        // logged "it may now write" and then said nothing at all for two hours.
        //
        // Placed at the LOOP rather than inside the production `Peer` impl deliberately: here it
        // covers every `PuzzleStateSource`, and it is reachable by a test double — a deadline that
        // only exists on the one implementation no test can construct is a deadline nothing can
        // prove. Recovery is already wired: this error reaches the supervisor's `catch-up failed`
        // path, which drops the peer and backs off.
        let respond = tokio::time::timeout(
            PEER_REQUEST_TIMEOUT,
            peer.request_puzzle_state(requested.clone(), previous_height, header_hash),
        )
        .await
        .map_err(|_| {
            SyncError::Peer(format!(
                "the peer did not answer a puzzle-state request within {}s",
                PEER_REQUEST_TIMEOUT.as_secs()
            ))
        })??;
        if first_batch {
            events.publish(SyncEvent::Subscribed);
            first_batch = false;
        }

        // Charged BEFORE the write, so a batch that busts either bound never lands (F4).
        budget.charge(respond.coin_states.len())?;
        // An unfinished batch must STRICTLY advance. `is_finished` is a bit the peer chooses,
        // and the loop's only other exit is the peer's goodwill: answering `false` forever at a
        // constant height is a free unbounded write loop against `wallet.sqlite`.
        if !respond.is_finished {
            if let Some(previous) = previous_height {
                if respond.height <= previous {
                    return Err(SyncError::CatchUpNotAdvancing {
                        height: respond.height,
                        previous,
                    });
                }
            }
        }

        if epoch_at_first_write.is_none() {
            epoch_at_first_write = Some(db.reset_epoch().await?);
        }
        apply_coin_states(db, &respond.coin_states, &subscribed, derived).await?;
        events.publish(SyncEvent::PuzzleBatchSynced);

        if respond.is_finished {
            // ONE statement ends the catch-up: the peak, the authoritative flag, and the arrival
            // baseline are armed together from this response's own values. Splitting them is how
            // the baseline came to be armable by a caller that had replayed nothing
            // (dig_ecosystem#2548) -- see `WalletDb::complete_catch_up`.
            let recorded = db
                .complete_catch_up_unless_reset(
                    &CatchUpReplay::finished_at(
                        authority.ceiling(),
                        respond.height,
                        hex::encode(respond.header_hash),
                        // Coverage recorded as ADDRESSES, matching every reader of
                        // `covered_puzzle_hashes` (`covers` is a containment test over the wallet's own
                        // hashes). Recording the union here would make the replica claim coverage of a
                        // set it does not answer for.
                        &addresses,
                    )?,
                    epoch_at_first_write.expect(
                        "the epoch is read before the first write, which precedes any terminal",
                    ),
                )
                .await?;
            if !recorded {
                // The coin database was reset while this replay was in flight, so everything
                // it wrote was discarded. Reporting success here would be the money lie: the
                // flag would declare an emptied or partially refilled table authoritative.
                return Err(SyncError::ResetDuringCatchUp);
            }
            return Ok(());
        }
        // Continue from where this batch ended.
        previous_height = Some(respond.height);
        header_hash = respond.header_hash;
    }
}

/// Consume peer pushes on the receiver until it closes: `coin_state_update` →
/// [`handle_coin_state_update`]; `new_peak_wallet` → advance the peak, but ONLY from an
/// authoritative peer — a [`PeerTrust::Discovered`] peer's height is dropped here, for the same
/// reason its coins are (see [`PeerTrust`]). This is the production loop run after
/// [`initial_sync_with_authority`]; it returns when the peer disconnects, at which point it publishes
/// [`SyncEvent::Stop`] on `events`.
///
/// When `attributor` is `Some`, each applied `coin_state_update` is followed by a CAT/
/// singleton attribution pass (#407) so newly-synced CAT coins gain their `asset_id`. When
/// `None`, coins are stored as-is (attribution runs elsewhere / not at all).
///
/// `session` carries the puzzle-hash set this session actually subscribed (pushed coins outside
/// it are dropped — see [`apply_coin_states`]; an empty set is meaningful and correct, because a
/// nothing-subscribed session writes no coins), how far its peer is
/// trusted ([`PeerTrust`]), and its cumulative rollback allowance.
pub async fn run_update_loop(
    db: &WalletDb,
    mut receiver: tokio::sync::mpsc::Receiver<Message>,
    events: &EventBus,
    attributor: Option<&CatAttributor<'_>>,
    session: &mut SessionState<'_>,
) -> Result<(), SyncError> {
    while let Some(message) = receiver.recv().await {
        match message.msg_type {
            ProtocolMessageTypes::CoinStateUpdate => {
                if let Ok(update) = decode::<CoinStateUpdate>(&message) {
                    let applied = handle_coin_state_update(db, &update, events, session).await?;
                    // Only after a frame that actually WROTE something. See [`FrameApplied`].
                    if applied == FrameApplied::Applied {
                        if let Some(a) = attributor {
                            a.attribute(db).await?;
                            // dig-node#546 — the second of this frame's two drain attempts. See
                            // [`record_arrivals_or_log`] for why one call inside
                            // `handle_coin_state_update` is not enough: attribution can only
                            // promote a staged CAT AFTER that call already ran, so without this,
                            // the promoted coin's hold is examined only on the NEXT frame — which
                            // may never come.
                            record_arrivals_or_log(db, session, update.height).await;
                        }
                    }
                }
            }
            ProtocolMessageTypes::NewPeakWallet => {
                if let Ok(peak) = decode::<NewPeakWallet>(&message) {
                    // A discovered peer's height is not written, for the same reason its coins
                    // are not: `new_peak_wallet` is the CHEAPEST frame on the wire to lie in,
                    // and the value it would land in is the one a caller divides into a
                    // confirmation count (see [`PeerTrust`]).
                    if !session.authority.trust().is_authoritative() {
                        tracing::debug!(
                            claimed = peak.height,
                            "wallet sync: dropping a new_peak_wallet from a discovered peer"
                        );
                        continue;
                    }
                    // Checked BEFORE the backwards check, so a refused claim is never also
                    // evaluated as a retreat. A refusal deliberately leaves the replica peak
                    // STILL, which is the correct observable: the phase report then shows the real
                    // gap and the stall detector accumulates toward its deadline. The bound and
                    // those two guards COMPOSE rather than masking each other — which is the point,
                    // because an inflated peak is what would permanently silence both.
                    let admitted = match session.admit_peak(peak.height)? {
                        PeakClaim::Admitted(admitted) => admitted,
                        PeakClaim::Refused => continue,
                    };
                    let state = db.sync_state().await?;
                    // The recorded peak only ever ADVANCES here. This value is served on OPEN
                    // reads and is what a caller bounding a claimed confirmation reads, so a
                    // peer that can drive it downwards can make settled money read unconfirmed
                    // (inviting a second send) — and `new_peak_wallet` carries no fork point to
                    // justify a retreat. The authoritative way a peak legitimately moves back is
                    // `coin_state_update`, which carries `fork_height` and unlatches the routing
                    // gate; a bare backwards peak claim is simply refused.
                    if state
                        .peak_height
                        .is_some_and(|current| peak.height < current)
                    {
                        tracing::warn!(
                            claimed = peak.height,
                            current = ?state.peak_height,
                            "wallet sync: refusing a backwards new_peak_wallet"
                        );
                        continue;
                    }
                    db.record_peak(admitted, state.header_hash.as_deref().unwrap_or(""))
                        .await?;
                }
            }
            _ => {}
        }
    }
    events.publish(SyncEvent::Stop);
    Ok(())
}

fn decode<T: chia_traits::Streamable>(message: &Message) -> Result<T, SyncError> {
    T::from_bytes(&message.data).map_err(|e| SyncError::Peer(format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sage::db::WalletDb;
    use crate::sage::sync_supervisor::{
        FollowingEvidence, StallVerdict, StallWatch, SESSION_MAX_LIFETIME, STALL_AFTER,
    };

    fn coin(parent: u8, ph: u8, amount: u64) -> Coin {
        Coin {
            parent_coin_info: Bytes32::new([parent; 32]),
            puzzle_hash: Bytes32::new([ph; 32]),
            amount,
        }
    }

    /// The puzzle hash every fixture coin below sits at, and the one the tests subscribe.
    const OWNED: u8 = 9;

    /// The subscription a session would have made over [`OWNED`].
    fn subscribed_owned() -> SubscribedHashes {
        HashSet::from([Bytes32::new([OWNED; 32])])
    }

    /// A session over `subscribed` whose peer the OPERATOR chose — full authority.
    fn operator(subscribed: &SubscribedHashes) -> SessionState<'_> {
        SessionState::with_authority(subscribed, WriteAuthority::Operator)
    }

    /// A `new_peak_wallet` frame claiming `height`, exactly as it arrives on the wire.
    fn new_peak_message(height: u32) -> Message {
        let peak = NewPeakWallet {
            header_hash: Bytes32::new([3; 32]),
            height,
            weight: 0u128,
            fork_point_with_previous_peak: 0,
        };
        Message {
            msg_type: ProtocolMessageTypes::NewPeakWallet,
            id: None,
            data: chia_traits::Streamable::to_bytes(&peak).unwrap().into(),
        }
    }

    /// A session over a peer this node merely DISCOVERED — writes nothing.
    fn discovered(subscribed: &SubscribedHashes) -> SessionState<'_> {
        SessionState::with_authority(subscribed, WriteAuthority::Discovered)
    }

    /// A session over a DISCOVERED peer a quorum settled at `anchor` — full authority, bounded.
    fn corroborated(subscribed: &SubscribedHashes, anchor: u32) -> SessionState<'_> {
        SessionState::with_authority(
            subscribed,
            WriteAuthority::Corroborated(PeakCeiling::from_corroborated(
                anchor,
                SESSION_MAX_LIFETIME,
            )),
        )
    }

    /// The ceiling a session elevated at `anchor` carries, at the shipped session lifetime.
    fn ceiling_at(anchor: u32) -> PeakCeiling {
        PeakCeiling::from_corroborated(anchor, SESSION_MAX_LIFETIME)
    }

    /// Feed `frames` through [`run_update_loop`] on `session` and return what it concluded.
    ///
    /// The channel is closed before the loop starts, so the loop always terminates on its own: a
    /// regression here fails LOUDLY rather than hanging, and a hanging test in this crate is
    /// indistinguishable from a dead agent.
    async fn feed(
        db: &WalletDb,
        session: &mut SessionState<'_>,
        frames: Vec<Message>,
    ) -> Result<(), SyncError> {
        let events = EventBus::default();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        for frame in frames {
            tx.send(frame).await.unwrap();
        }
        drop(tx);
        run_update_loop(db, rx, &events, None, session).await
    }

    fn state(c: Coin, created: Option<u32>, spent: Option<u32>) -> CoinState {
        CoinState {
            coin: c,
            created_height: created,
            spent_height: spent,
        }
    }

    /// **THE #380 INGESTION DROP.** A coin at a DERIVED CAT hash must reach the wallet at all.
    ///
    /// This is the starvation the ticket measured: on `origin/main` `apply_coin_states` keeps only
    /// coins whose puzzle hash is in `subscribed`, and a CAT coin never sits at its owner's
    /// address — it sits at the outer hash that curries the asset id around it. On a real wallet
    /// that dropped **50 of the 51** puzzle hashes actually holding its coins, so the attributor
    /// downstream was starved rather than broken.
    ///
    /// Deliberately paired with an ORDINARY p2 coin in the same batch. Without it the assertion
    /// "`coins` has one row" would be satisfied by an implementation that admitted the CAT coin
    /// straight into `coins` — the round-5 defect — and by one that routed it correctly, alike.
    #[tokio::test]
    async fn a_derived_cat_hash_coin_is_staged_while_a_p2_coin_is_admitted() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let owner = Bytes32::new([OWNED; 32]);
        let asset = Bytes32::new([0xDA; 32]);
        let derived = DerivedCats::derive(&[owner], &[asset]);
        let outer = derived.hashes()[0];

        let plain_coin = Coin {
            parent_coin_info: Bytes32::new([1; 32]),
            puzzle_hash: owner,
            amount: 5_000,
        };
        let cat_coin = Coin {
            parent_coin_info: Bytes32::new([2; 32]),
            puzzle_hash: outer,
            amount: 7_000,
        };
        let subscribed: SubscribedHashes = [owner].into_iter().collect();

        apply_coin_states(
            &db,
            &[
                state(plain_coin, Some(10), None),
                state(cat_coin, Some(10), None),
            ],
            &subscribed,
            &derived,
        )
        .await
        .unwrap();

        // The CAT coin ARRIVED — it is not dropped, which is the whole of #380 …
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            1,
            "a coin at a derived CAT hash must be staged, not dropped at ingest"
        );
        // … and it is not BELIEVED, which is the whole of the round-5 rejection.
        let believed = db.all_coins().await.unwrap();
        assert_eq!(
            believed.len(),
            1,
            "only the ordinary p2 coin may enter `coins`"
        );
        assert_eq!(believed[0].coin_id, hex::encode(plain_coin.coin_id()));
        assert_eq!(
            db.balance(None).await.unwrap(),
            5_000,
            "the staged CAT coin must not be counted as XCH"
        );
    }

    /// A peer that answers one batch with whatever coin states it was built with, and RECORDS the
    /// puzzle-hash vector it was asked about.
    ///
    /// Recording the request is the half that makes the test two-sided. Asserting only "the coin
    /// did not enter `coins`" is satisfied identically by a correct split and by a catch-up that
    /// never asked about the derived hash at all — and the second is the #380 starvation this
    /// family already fixed once. Coverage and admission must both be observable, or a regression
    /// can trade one for the other and stay green.
    struct RecordingPeer {
        states: Vec<CoinState>,
        requested: std::sync::Arc<std::sync::Mutex<Vec<Bytes32>>>,
    }

    #[async_trait::async_trait]
    impl PuzzleStateSource for RecordingPeer {
        async fn request_puzzle_state(
            &self,
            puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            *self.requested.lock().unwrap() = puzzle_hashes;
            Ok(RespondPuzzleState {
                puzzle_hashes: vec![],
                coin_states: self.states.clone(),
                height: 6_000_000,
                header_hash: Bytes32::new([9; 32]),
                is_finished: true,
            })
        }
    }

    /// **Proves (dig-node#394, gate finding 1):** the CATCH-UP path routes a derived-hash coin to
    /// staging, and never into `coins` as XCH — while still ASKING the peer about that hash.
    ///
    /// THE BUG THIS PINS. `sync_supervisor.rs` unioned the addresses with the derived CAT hashes
    /// and passed one vector down; `initial_sync_with_authority` then built the admission set from
    /// that widened vector, so a coin at any derived hash was admitted and typed `asset_id: None`
    /// — which means XCH in this schema. One `CREATE_COIN` at `cat_puzzle_hash(victim_p2, asset)`,
    /// needing only the victim's public address, bought a fabricated XCH balance plus a permanent
    /// send kill-switch, and the catch-up re-runs on every reconnect.
    ///
    /// FIXTURE DESIGN — three things, each load-bearing:
    ///
    /// - `derived` is NOT `DerivedCats::default()`. Every pre-existing catch-up test passed the
    ///   default, and a field every fixture sets to the same value is a field the suite cannot
    ///   test. That collapse is the entire reason this defect reached a security gate.
    /// - An ORDINARY p2 coin rides in the same batch, as a truthful control. Without it,
    ///   `all_coins().len() == 0` would also be satisfied by a catch-up that admitted nothing at
    ///   all, which is a different bug wearing this one's assertion.
    /// - The FABRICATED amount is large and the honest one small, so the XCH balance assertion is
    ///   a concrete figure rather than a symbol that moves with the code under test.
    #[tokio::test]
    async fn the_catch_up_never_admits_a_derived_hash_coin_as_xch() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();
        let owner = Bytes32::new([OWNED; 32]);
        let asset = Bytes32::new([0xDA; 32]);
        let derived = DerivedCats::derive(&[owner], &[asset]);
        let outer = derived.hashes()[0];

        let honest = Coin {
            parent_coin_info: Bytes32::new([1; 32]),
            puzzle_hash: owner,
            amount: 5_000,
        };
        // What an attacker places: one CREATE_COIN at the derived hash, for a number the victim
        // will read as their balance.
        let fabricated = Coin {
            parent_coin_info: Bytes32::new([2; 32]),
            puzzle_hash: outer,
            amount: 999_999_999,
        };
        let requested = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer = RecordingPeer {
            states: vec![
                state(honest, Some(10), None),
                state(fabricated, Some(10), None),
            ],
            requested: std::sync::Arc::clone(&requested),
        };

        initial_sync_with_authority(
            &peer,
            &db,
            // ADDRESSES ONLY, exactly as the supervisor now passes them.
            vec![owner],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Operator,
            &derived,
        )
        .await
        .unwrap();

        // COVERAGE: the peer WAS asked about the derived hash. Drop this and the fix could be
        // "stop subscribing derived hashes", which re-opens #380's starvation.
        let asked = requested.lock().unwrap().clone();
        assert!(
            asked.contains(&outer),
            "the catch-up must still ASK about the derived CAT hash: coverage is not admission"
        );
        assert!(asked.contains(&owner), "and about the wallet's own address");

        // ADMISSION: the fabricated coin is staged, not believed.
        let believed = db.all_coins().await.unwrap();
        assert_eq!(
            believed.len(),
            1,
            "only the ordinary p2 coin may enter `coins` on the catch-up path"
        );
        assert_eq!(believed[0].coin_id, hex::encode(honest.coin_id()));
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            1,
            "the derived-hash coin must be STAGED, not dropped"
        );

        // The money figures, pinned concretely. `999_999_999` is the value the gate reproduced as
        // a fabricated XCH balance against the previous head.
        assert_eq!(
            db.balance(None).await.unwrap(),
            5_000,
            "a coin at a derived CAT hash must never be counted as XCH"
        );
        // Selection is largest-first and a fabricated coin is unspendable by anyone, so admitting
        // one is a permanent XCH send kill-switch, not merely a wrong figure.
        assert_eq!(
            db.unspent_coins(None).await.unwrap().len(),
            1,
            "and must never become a selectable XCH spend input"
        );
    }

    /// **Proves (dig-node#394):** admission cannot be widened THROUGH the address parameter either.
    ///
    /// The companion to the test above, and the one that makes the guarantee structural rather
    /// than a convention. Above, the caller behaves; here the caller misbehaves and hands a
    /// derived hash in the ADDRESS vector — the exact shape of the defect, one refactor away from
    /// returning. `initial_sync_with_authority` filters it back out, so there is no vector of any
    /// kind by which a derived hash reaches the admission set.
    #[tokio::test]
    async fn a_derived_hash_offered_as_an_address_is_refused_admission() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();
        let owner = Bytes32::new([OWNED; 32]);
        let derived = DerivedCats::derive(&[owner], &[Bytes32::new([0xDA; 32])]);
        let outer = derived.hashes()[0];

        let fabricated = Coin {
            parent_coin_info: Bytes32::new([2; 32]),
            puzzle_hash: outer,
            amount: 999_999_999,
        };
        let peer = RecordingPeer {
            states: vec![state(fabricated, Some(10), None)],
            requested: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        initial_sync_with_authority(
            &peer,
            &db,
            // The MISBEHAVING caller: the derived hash smuggled in as an address.
            vec![owner, outer],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Operator,
            &derived,
        )
        .await
        .unwrap();

        assert_eq!(
            db.all_coins().await.unwrap().len(),
            0,
            "a derived hash passed as an address must still not admit its coin"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "and must contribute nothing to the XCH balance"
        );
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            1,
            "it is staged instead — discovered, not believed"
        );
    }

    /// A coin at a hash NEITHER set knows is still dropped, exactly as on `main`.
    ///
    /// The control for the test above: staging must widen what the wallet accepts by precisely the
    /// derived set and by nothing else.
    #[tokio::test]
    async fn an_unknown_puzzle_hash_is_still_dropped() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let owner = Bytes32::new([OWNED; 32]);
        let derived = DerivedCats::derive(&[owner], &[Bytes32::new([0xDA; 32])]);
        let stranger = Coin {
            parent_coin_info: Bytes32::new([3; 32]),
            puzzle_hash: Bytes32::new([0x77; 32]),
            amount: 1,
        };
        let subscribed: SubscribedHashes = [owner].into_iter().collect();

        apply_coin_states(
            &db,
            &[state(stranger, Some(10), None)],
            &subscribed,
            &derived,
        )
        .await
        .unwrap();

        assert!(db.all_coins().await.unwrap().is_empty());
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 0);
    }

    /// A derived CAT hash can never reach the arrivals notifier, because the two sets are separate
    /// FIELDS and only the address set is passed to it.
    ///
    /// This is the `sync.rs:957` defect class made unreachable rather than guarded: a false
    /// *"you were paid"* notice came from exactly this seam earlier in the ticket family. The
    /// ordinary p2 coin in the same batch is the truthful control — an implementation that simply
    /// stopped recording arrivals altogether would satisfy the first assertion and fail the second.
    #[tokio::test]
    async fn a_derived_cat_hash_never_reaches_the_arrivals_notifier() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let owner = Bytes32::new([OWNED; 32]);
        let derived = DerivedCats::derive(&[owner], &[Bytes32::new([0xDA; 32])]);
        let subscribed: SubscribedHashes = [owner].into_iter().collect();

        // The set handed to `record_arrivals` is `session.subscribed`, which holds ADDRESSES only.
        let state = SessionState::with_authority(&subscribed, WriteAuthority::Operator)
            .following_derived_cats(&derived);
        let watched: Vec<String> = state.subscribed.iter().map(hex::encode).collect();

        assert!(
            watched.contains(&hex::encode(owner)),
            "the notifier must still see the wallet's own addresses"
        );
        assert!(
            !watched.contains(&hex::encode(derived.hashes()[0])),
            "an outer CAT hash must never be presented to the notifier as an address"
        );
        let _ = &db;
    }

    #[tokio::test]
    async fn apply_coin_states_persists_and_computes_balance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let states = vec![
            state(coin(1, 9, 1_000), Some(10), None),
            state(coin(2, 9, 2_000), Some(11), None),
        ];
        apply_coin_states(&db, &states, &subscribed_owned(), &DerivedCats::default())
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 3_000);
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn later_spend_state_marks_coin_spent() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let c = coin(1, 9, 500);
        apply_coin_states(
            &db,
            &[state(c, Some(10), None)],
            &subscribed_owned(),
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 500);
        // The peer later reports the same coin as spent.
        apply_coin_states(
            &db,
            &[state(c, Some(10), Some(20))],
            &subscribed_owned(),
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 0);
    }

    // ---- arrivals over the LIVE path (dig_ecosystem#2548) ------------------

    /// TRAP 1, through the real code path rather than the recorder alone: a catch-up replays the
    /// whole address history through [`apply_coin_states`], and a live update over that history
    /// must announce none of it.
    #[tokio::test]
    async fn the_replayed_history_a_reconnect_writes_is_never_announced() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let subscribed = subscribed_owned();

        // The catch-up: history written, then the flag that arms the baseline.
        apply_coin_states(
            &db,
            &[
                state(coin(1, OWNED, 5_000), Some(10), None),
                state(coin(2, OWNED, 7_000), Some(20), None),
            ],
            &subscribed,
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 20, "aa", &[]).unwrap())
            .await
            .unwrap();

        // A reconnect replays the same history verbatim, and a live frame lands on top of it.
        apply_coin_states(
            &db,
            &[
                state(coin(1, OWNED, 5_000), Some(10), None),
                state(coin(2, OWNED, 7_000), Some(20), None),
            ],
            &subscribed,
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        let events = EventBus::default();
        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 21,
                fork_height: 21,
                peak_hash: Bytes32::new([1; 32]),
                items: vec![],
            },
            &events,
            &mut operator(&subscribed),
        )
        .await
        .unwrap();
        assert!(db.arrivals_since(0, 100).await.unwrap().is_empty());

        // POSITIVE CONTROL: a genuinely new coin on the next frame IS announced, so the assertion
        // above cannot be satisfied by a path that records nothing at all.
        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 22,
                fork_height: 22,
                peak_hash: Bytes32::new([1; 32]),
                items: vec![state(coin(3, OWNED, 900), Some(22), None)],
            },
            &events,
            &mut operator(&subscribed),
        )
        .await
        .unwrap();
        let arrivals = db.arrivals_since(0, 100).await.unwrap();
        assert_eq!(arrivals.len(), 1);
        assert_eq!(arrivals[0].amount, "900");
        assert_eq!(arrivals[0].confirmed_height, 22);
        assert_eq!(arrivals[0].asset_id, None);
    }

    /// TRAP 4 over the live path, in the shape that actually occurs: the spent parent and the
    /// change coin it created arrive in the SAME frame, change first. Only the stranger's payment
    /// is announced.
    #[tokio::test]
    async fn change_arriving_in_the_same_frame_as_its_parent_is_not_announced() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let subscribed = subscribed_owned();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "aa", &[]).unwrap())
            .await
            .unwrap();

        let funding = coin(1, OWNED, 10_000);
        let change = Coin {
            parent_coin_info: funding.coin_id(),
            puzzle_hash: Bytes32::new([OWNED; 32]),
            amount: 4_000,
        };
        let gift = coin(2, OWNED, 250);

        let events = EventBus::default();
        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 101,
                fork_height: 101,
                peak_hash: Bytes32::new([1; 32]),
                // Change BEFORE its parent, which is the order the peer is free to choose.
                items: vec![
                    state(change, Some(101), None),
                    state(funding, Some(101), Some(101)),
                    state(gift, Some(101), None),
                ],
            },
            &events,
            &mut operator(&subscribed),
        )
        .await
        .unwrap();

        let amounts: Vec<String> = db
            .arrivals_since(0, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.amount)
            .collect();
        // `funding` (foreign parent) and `gift` are arrivals; the 4_000 change is not.
        assert!(amounts.contains(&"10000".to_string()));
        assert!(amounts.contains(&"250".to_string()));
        assert!(
            !amounts.contains(&"4000".to_string()),
            "the wallet's own change was announced as an incoming payment: {amounts:?}"
        );
    }

    #[tokio::test]
    async fn coin_state_update_reorg_rolls_back_then_applies() {
        let db = WalletDb::open_in_memory().await.unwrap();
        // Build initial state at peak 40.
        apply_coin_states(
            &db,
            &[state(coin(1, 9, 5), Some(10), Some(30))],
            &subscribed_owned(),
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        db.set_peak(40, "aa").await.unwrap();

        // A reorg to fork_height 25 rolls back the spend@30, then applies the new items.
        let update = CoinStateUpdate {
            height: 45,
            fork_height: 25,
            peak_hash: Bytes32::new([7; 32]),
            items: vec![state(coin(2, 9, 8), Some(26), None)],
        };
        let events = EventBus::with_capacity(8);
        let mut rx = events.subscribe();
        handle_coin_state_update(&db, &update, &events, &mut operator(&subscribed_owned()))
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap(), SyncEvent::CoinState);

        // The rolled-back coin is unspent again (5) + the new coin (8) = 13.
        assert_eq!(db.balance(None).await.unwrap(), 13);
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(45));
    }

    #[tokio::test]
    async fn forward_update_advances_peak_without_rollback() {
        let db = WalletDb::open_in_memory().await.unwrap();
        apply_coin_states(
            &db,
            &[state(coin(1, 9, 5), Some(10), None)],
            &subscribed_owned(),
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        db.set_peak(40, "aa").await.unwrap();
        let update = CoinStateUpdate {
            height: 50,
            fork_height: 49, // above the current peak → no rollback
            peak_hash: Bytes32::new([1; 32]),
            items: vec![state(coin(2, 9, 3), Some(50), None)],
        };
        let events = EventBus::default();
        handle_coin_state_update(&db, &update, &events, &mut operator(&subscribed_owned()))
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 8);
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(50));
    }

    // -----------------------------------------------------------------------
    // The hostile peer (S1/S2/S3)
    //
    // The socket in front of `handle_coin_state_update` is untrusted: `connect_random_peer`
    // tries `127.0.0.1:8444` before any introducer, and the client accepts any certificate, so
    // an unprivileged co-resident process becomes the chain source on the next connect. These
    // fixtures are that process.
    // -----------------------------------------------------------------------

    /// A funded, caught-up replica: 6 XCH at [`OWNED`], created just below the peak, flag set.
    ///
    /// The wallet is FUNDED deliberately — an empty one cannot exhibit the defect, because the
    /// lie under test is "a balance that exists reads as a synced zero".
    async fn funded_and_synced() -> WalletDb {
        let db = WalletDb::open_in_memory().await.unwrap();
        apply_coin_states(
            &db,
            &[state(
                coin(1, OWNED, 6_000_000_000_000),
                Some(5_999_990),
                None,
            )],
            &subscribed_owned(),
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        db
    }

    /// **Proves (S1a, #2501):** a `coin_state_update` claiming a fork deeper than
    /// [`MAX_REORG_DEPTH`] is REFUSED — the replica is untouched and the session errors out.
    ///
    /// `fork_height: 0` is the whole table: `rollback_above(0)` deletes every coin. One frame.
    #[tokio::test]
    async fn a_reorg_deeper_than_the_bound_is_refused_and_the_replica_is_untouched() {
        let db = funded_and_synced().await;
        let events = EventBus::default();

        let err = handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 0,
                fork_height: 0,
                peak_hash: Bytes32::new([7; 32]),
                items: vec![],
            },
            &events,
            &mut operator(&subscribed_owned()),
        )
        .await
        .expect_err("a 6-million-block fork claim must be refused, not applied");

        assert!(
            matches!(
                err,
                SyncError::ForkTooDeep {
                    depth: 6_000_000,
                    max: MAX_REORG_DEPTH
                }
            ),
            "got {err:?}"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            6_000_000_000_000,
            "the replica must be intact — nothing was rolled back"
        );
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(6_000_000));
    }

    /// **Proves (S1b, #2501):** an ACCEPTED rollback (within the depth bound) clears
    /// `initial_sync_complete`, so an emptied replica stops being authoritative.
    ///
    /// This is the load-bearing half. The depth bound alone cannot fix the defect: a shallow
    /// rollback is legitimate protocol behaviour and still empties a wallet whose coins were all
    /// created recently. The fixture is built so the rollback SUCCEEDS and removes the funds —
    /// the observable that distinguishes a latch from a depth check is where the read routes
    /// afterwards, not whether the coin survived.
    #[tokio::test]
    async fn an_applied_rollback_stops_the_emptied_replica_being_authoritative() {
        let db = funded_and_synced().await;
        let events = EventBus::default();

        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 6_000_001,
                // 10 blocks below the peak: a depth a real reorg could plausibly have, and one
                // the bound therefore ACCEPTS. The wallet's only coin was created above it.
                fork_height: 5_999_990 - 1,
                peak_hash: Bytes32::new([7; 32]),
                items: vec![],
            },
            &events,
            &mut operator(&subscribed_owned()),
        )
        .await
        .expect("a shallow reorg is applied, not refused");

        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "the rollback did remove the coin — the fixture exercises the emptying path"
        );
        assert!(
            !db.is_synced().await.unwrap(),
            "an emptied replica must NOT stay initial-sync-complete"
        );
        assert_eq!(
            crate::sage::routing::route(db.is_synced().await.unwrap(), true),
            crate::sage::routing::Source::Fallback,
            "a funded wallet must never read 0 from a rolled-back replica as though synced"
        );
    }

    /// **Proves (S1c, #2501):** a peak that moves BACKWARDS without any rollback also clears the
    /// flag.
    ///
    /// `fork_height` at or above the peak skips the rollback branch entirely, so a latch wired
    /// only to the rollback would leave this replica claiming to be synced at a height it has
    /// not verified. The coin survives here, which is exactly why the balance is the wrong
    /// observable and the routing decision is the right one.
    #[tokio::test]
    async fn a_backwards_peak_in_a_coin_state_update_clears_the_sync_flag() {
        let db = funded_and_synced().await;
        let events = EventBus::default();

        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 1,
                fork_height: 6_000_000, // not below the peak → no rollback
                peak_hash: Bytes32::new([7; 32]),
                items: vec![],
            },
            &events,
            &mut operator(&subscribed_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            db.balance(None).await.unwrap(),
            6_000_000_000_000,
            "no rollback happened — the coin is still there"
        );
        assert!(
            !db.is_synced().await.unwrap(),
            "a replica whose peak went backwards is not caught up"
        );
    }

    /// **Proves (S2, #2501):** a `coin_state_update` may only write coins at hashes the session
    /// subscribed.
    ///
    /// The fixture pushes THREE coins in one frame: one at the subscribed hash (which must
    /// land, so the test cannot pass by dropping everything), and two at hashes that were never
    /// subscribed. A filter placed on the wrong side of the subscription would keep the
    /// foreign ones.
    #[tokio::test]
    async fn a_coin_state_update_cannot_write_coins_outside_the_subscription() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        let events = EventBus::default();

        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 6_000_001,
                fork_height: 6_000_000,
                peak_hash: Bytes32::new([7; 32]),
                items: vec![
                    state(coin(1, OWNED, 11), Some(6_000_001), None),
                    state(coin(2, FOREIGN, 1_000_000), Some(6_000_001), None),
                    state(coin(3, FOREIGN + 1, 2_000_000), Some(6_000_001), None),
                ],
            },
            &events,
            &mut operator(&subscribed_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            db.balance(None).await.unwrap(),
            11,
            "only the subscribed coin may be written"
        );
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 1);
    }

    /// **Proves (S3, #2501):** `new_peak_wallet` may only ADVANCE the replica peak.
    ///
    /// The peak is served on OPEN reads and is what bounds a claimed confirmation, so a peer
    /// that can drive it downwards makes settled money read unconfirmed. The forward peak in the
    /// same run is the control: without it a supervisor that ignored `new_peak_wallet` entirely
    /// would also pass.
    #[tokio::test]
    async fn new_peak_wallet_advances_but_never_retreats() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        let events = EventBus::default();
        let (tx, receiver) = tokio::sync::mpsc::channel::<Message>(4);

        for height in [6_000_010, 1] {
            let peak = NewPeakWallet {
                header_hash: Bytes32::new([3; 32]),
                height,
                weight: 0u128,
                fork_point_with_previous_peak: 0,
            };
            tx.send(Message {
                msg_type: ProtocolMessageTypes::NewPeakWallet,
                id: None,
                data: chia_traits::Streamable::to_bytes(&peak).unwrap().into(),
            })
            .await
            .unwrap();
        }
        drop(tx);

        run_update_loop(
            &db,
            receiver,
            &events,
            None,
            &mut operator(&subscribed_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(6_000_010),
            "the forward peak applies and the backwards one is refused"
        );
    }

    /// A peer that answers every subscription with "caught up, nothing here" — which is
    /// exactly what a real full node answers when you subscribe ZERO puzzle hashes. It is
    /// the counterfactual the guard exists to stop, so a test built on it fails loudly if
    /// the guard is removed rather than merely losing an error variant.
    struct CaughtUpAtOnce;

    #[async_trait::async_trait]
    impl PuzzleStateSource for CaughtUpAtOnce {
        async fn request_puzzle_state(
            &self,
            _puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            Ok(RespondPuzzleState {
                puzzle_hashes: vec![],
                coin_states: vec![],
                height: 6_000_000,
                header_hash: Bytes32::new([9; 32]),
                is_finished: true,
            })
        }
    }

    /// A peer that accepts the request and then never answers — the live incident's shape, and the
    /// one a socket-level check cannot see. The connection stays ESTABLISHED throughout.
    struct SilentPeer;

    #[async_trait::async_trait]
    impl PuzzleStateSource for SilentPeer {
        async fn request_puzzle_state(
            &self,
            _puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            std::future::pending().await
        }
    }

    /// **Proves (dig_ecosystem#2851):** a peer that goes SILENT mid-catch-up ends the catch-up with
    /// an error instead of parking the supervisor for ever.
    ///
    /// THE BUG THIS PINS. `request_puzzle_state` was awaited bare, so one unanswered round trip
    /// parked `initial_sync_with_authority` — which runs BEFORE the supervisor's `select!` and is therefore
    /// outside every exit the supervisor has. The observed result was a node that logged "it may now
    /// write" and then said nothing for two hours, with the peer's socket still ESTABLISHED.
    ///
    /// FIXTURE DESIGN — the double parks rather than erroring, because an erroring peer takes the
    /// path that already worked and would pass against the defect. The clock is PAUSED, so the
    /// assertion is "a deadline exists", not "sixty seconds elapsed", and the outer bound is what
    /// makes a regression fail LOUDLY: with no deadline the only timer left is that bound, the
    /// paused clock jumps straight to it, and the test fails instead of hanging like a dead process.
    #[tokio::test]
    async fn a_silent_peer_times_out_instead_of_parking_the_catch_up() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();
        // Paused only AFTER the DB is open: the sqlite pool has acquisition timers of its own, and
        // a virtual clock running while it connects auto-advances straight through them.
        tokio::time::pause();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            initial_sync_with_authority(
                &SilentPeer,
                &db,
                vec![Bytes32::new([7; 32])],
                Bytes32::new([0; 32]),
                "127.0.0.1",
                &events,
                WriteAuthority::Operator,
                &DerivedCats::default(),
            ),
        )
        .await
        .expect("the catch-up never returned: a silent peer still parks the supervisor for ever");

        let err = outcome.expect_err("a peer that never answered must not report success");
        assert!(
            matches!(&err, SyncError::Peer(m) if m.contains("did not answer")),
            "the failure must name the timeout as the reason; got {err:?}"
        );
        // Back to the real clock before touching the DB again: a pool acquisition under a virtual
        // one auto-advances straight through its own timeout, which fails as `PoolTimedOut` on a
        // cold connection and passes on a warm one — green locally, red in CI.
        tokio::time::resume();
        assert!(
            !db.is_synced().await.unwrap(),
            "a timed-out catch-up must not latch initial_sync_complete"
        );
    }

    /// **Proves (T1, #2501):** [`initial_sync_with_authority`] REFUSES an empty puzzle-hash set, and
    /// the DB is left un-synced.
    ///
    /// The peer double here would happily report `is_finished` on the first response, so
    /// without the guard the function reaches `force_initial_sync_complete_for_test(true)` over a DB
    /// that was never queried for a single coin — and `routing::route(true, true)` then
    /// answers every wallet-scoped read from it. This is the floor of that invariant.
    #[tokio::test]
    async fn initial_sync_refuses_an_empty_puzzle_hash_set() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();

        let err = initial_sync_with_authority(
            &CaughtUpAtOnce,
            &db,
            vec![],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Operator,
            &DerivedCats::default(),
        )
        .await
        .expect_err("an empty subscription set must be refused, not performed");

        assert!(matches!(err, SyncError::NoPuzzleHashes), "got {err:?}");
        assert!(
            !db.is_synced().await.unwrap(),
            "the initial-sync-complete flag must NOT be set over an empty subscription"
        );
        assert_eq!(
            crate::sage::routing::route(db.is_synced().await.unwrap(), true),
            crate::sage::routing::Source::Fallback,
            "wallet-scoped reads must still route to the fallback, not the empty DB"
        );
    }

    /// A peer that genuinely ANSWERS the subscription — one coin at the subscribed hash — and
    /// also slips in a coin at a hash that was never subscribed.
    ///
    /// The honest coin is what makes this a control rather than another vacuous double: a
    /// catch-up that completes here has actually transferred state, so the completion flag is
    /// backed by something. The foreign coin rides along because the filter and the flag are
    /// exercised by the same call, and a peer that can lie about one can lie about both.
    struct AnswersSubscriptionAndSlipsOneIn;

    /// The hash the fixtures never subscribe.
    const FOREIGN: u8 = 200;

    #[async_trait::async_trait]
    impl PuzzleStateSource for AnswersSubscriptionAndSlipsOneIn {
        async fn request_puzzle_state(
            &self,
            puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            Ok(RespondPuzzleState {
                puzzle_hashes: puzzle_hashes.clone(),
                coin_states: vec![
                    state(coin(1, OWNED, 700), Some(5_999_000), None),
                    state(coin(2, FOREIGN, 999_999), Some(5_999_001), None),
                ],
                height: 6_000_000,
                header_hash: Bytes32::new([9; 32]),
                is_finished: true,
            })
        }
    }

    /// **Proves (control + S2, #2501):** the catch-up path DOES complete — and sets the flag —
    /// once there is at least one puzzle hash AND the peer actually answers with that wallet's
    /// coins; and a coin at an unsubscribed hash in the SAME response is dropped.
    ///
    /// The earlier version of this control used a peer answering `is_finished, coin_states: []`,
    /// which encoded "a peer says caught-up-and-you-own-nothing, so flip the flag" as the
    /// intended behaviour — the exact shape of the money lie the rest of this module defends
    /// against. The peer here has to transfer real state to satisfy it.
    #[tokio::test]
    async fn initial_sync_completes_and_ignores_coins_outside_the_subscription() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();

        initial_sync_with_authority(
            &AnswersSubscriptionAndSlipsOneIn,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Operator,
            &DerivedCats::default(),
        )
        .await
        .expect("a non-empty subscription set catches up normally");

        assert!(db.is_synced().await.unwrap());
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(6_000_000));
        assert_eq!(
            db.balance(None).await.unwrap(),
            700,
            "only the subscribed coin may be persisted — the foreign one is not the wallet's"
        );
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 1);
    }

    /// **Proves:** [`run_update_loop`] publishes [`SyncEvent::Stop`] when its receiver
    /// channel closes (the peer disconnected / shutdown), even with zero messages processed.
    #[tokio::test]
    async fn run_update_loop_publishes_stop_on_channel_close() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::with_capacity(8);
        let mut rx = events.subscribe();
        let (tx, receiver) = tokio::sync::mpsc::channel::<Message>(1);
        drop(tx); // closes the channel immediately

        run_update_loop(
            &db,
            receiver,
            &events,
            None,
            &mut operator(&subscribed_owned()),
        )
        .await
        .unwrap();

        assert_eq!(rx.recv().await.unwrap(), SyncEvent::Stop);
    }

    /// **Proves:** [`handle_coin_state_update`] publishes exactly one [`SyncEvent::CoinState`]
    /// per applied update via [`run_update_loop`]'s dispatch path.
    #[tokio::test]
    async fn run_update_loop_publishes_coin_state_per_update() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(10, "aa").await.unwrap();
        let events = EventBus::with_capacity(8);
        let mut rx = events.subscribe();
        let (tx, receiver) = tokio::sync::mpsc::channel::<Message>(4);

        let update = CoinStateUpdate {
            height: 11,
            fork_height: 10,
            peak_hash: Bytes32::new([2; 32]),
            items: vec![state(coin(3, 9, 42), Some(11), None)],
        };
        let msg = Message {
            msg_type: ProtocolMessageTypes::CoinStateUpdate,
            id: None,
            data: chia_traits::Streamable::to_bytes(&update).unwrap().into(),
        };
        tx.send(msg).await.unwrap();
        drop(tx);

        run_update_loop(
            &db,
            receiver,
            &events,
            None,
            &mut operator(&subscribed_owned()),
        )
        .await
        .unwrap();

        assert_eq!(rx.recv().await.unwrap(), SyncEvent::CoinState);
        assert_eq!(rx.recv().await.unwrap(), SyncEvent::Stop);
        assert_eq!(db.balance(None).await.unwrap(), 42);
    }

    // -----------------------------------------------------------------------
    // The trust boundary (F1/F5, #2501 re-audit)
    //
    // A peer reached by DISCOVERY - a DNS introducer answer, or the `127.0.0.1:8444` probe any
    // co-resident process can answer - is advisory. These tests hold that boundary at the two
    // functions that can breach it.
    // -----------------------------------------------------------------------

    /// **Proves (F1a):** a DISCOVERED peer can never set `initial_sync_complete`, and therefore
    /// can never make its own answers authoritative for money.
    ///
    /// The peer double is [`AnswersSubscriptionAndSlipsOneIn`] - the HONEST one, which transfers
    /// real state and which the control test above shows completing a catch-up successfully.
    /// That choice is deliberate: a hostile double would fail this test for half a dozen other
    /// reasons and prove nothing about trust. The ONLY difference between this call and the
    /// passing control is the [`PeerTrust`] argument, so the refusal can only come from the
    /// trust check.
    #[tokio::test]
    async fn a_discovered_peer_can_never_set_the_initial_sync_flag() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();

        let err = initial_sync_with_authority(
            &AnswersSubscriptionAndSlipsOneIn,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Discovered,
            &DerivedCats::default(),
        )
        .await
        .expect_err("a discovered peer must not be allowed to run a catch-up");

        assert!(matches!(err, SyncError::UntrustedPeer), "got {err:?}");
        assert!(
            !db.is_synced().await.unwrap(),
            "a discovered peer must never latch the routing gate"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "and must not have written any coins on the way to being refused"
        );
        assert_eq!(
            crate::sage::routing::route(db.is_synced().await.unwrap(), true),
            crate::sage::routing::Source::Fallback,
        );
    }

    /// **Proves (F1b, the auditor's reconnect exploit):** the emptying frame that fired the latch
    /// in the previous round does NOTHING when it comes from a discovered peer - and the
    /// catch-up it would have re-latched over on the next reconnect is refused too.
    ///
    /// This drives the exploit in its recorded order: a funded, operator-established replica; a
    /// `CoinStateUpdate` forking 11 blocks below the peak (inside [`MAX_REORG_DEPTH`], so the
    /// depth bound accepts it); then the reconnect the attacker buys by closing the socket. The
    /// wallet is FUNDED because the lie under test is "money that exists reads as a synced
    /// zero", which an empty fixture cannot exhibit.
    #[tokio::test]
    async fn a_discovered_peer_cannot_empty_a_funded_replica_or_re_latch_after_a_reconnect() {
        let db = funded_and_synced().await;
        let events = EventBus::default();
        let subscribed = subscribed_owned();

        // Frame 1: the rollback that emptied the table last round.
        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 6_000_001,
                fork_height: 5_999_990 - 1,
                peak_hash: Bytes32::new([7; 32]),
                items: vec![],
            },
            &events,
            &mut discovered(&subscribed),
        )
        .await
        .expect("a discovered-peer frame is dropped whole, not an error");

        assert_eq!(
            db.balance(None).await.unwrap(),
            6_000_000_000_000,
            "a discovered peer must not be able to roll the replica back"
        );
        assert!(
            db.is_synced().await.unwrap(),
            "and must not be able to unlatch what an operator peer established"
        );

        // The attacker closes the socket; the supervisor reconnects to it and the catch-up that
        // re-latched over an empty response last round is now refused at the floor.
        let err = initial_sync_with_authority(
            &CaughtUpAtOnce,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Discovered,
            &DerivedCats::default(),
        )
        .await
        .expect_err("the reconnect must not buy a fresh catch-up");
        assert!(matches!(err, SyncError::UntrustedPeer), "got {err:?}");
        assert_eq!(
            db.balance(None).await.unwrap(),
            6_000_000_000_000,
            "the funded balance survives the whole exploit"
        );
    }

    /// **Proves (F1c, the corrected shape):** a discovered peer's `coin_state_update` leaves
    /// `sync_state` COMPLETELY unchanged — including the peak, which the previous round let it
    /// advance.
    ///
    /// **Why `u32::MAX` and not some ordinary higher height.** The defect this pins is not "the
    /// peak can be nudged"; it is that a confirmation count is `peak − created_height`, so the
    /// forward direction is the DANGEROUS one. `u32::MAX` is the value at which a spend that
    /// never landed reads as ~4.29e9 confirmations, and it is one frame away on the wire. A
    /// fixture that moved the peak by a plausible-looking amount would assert the same equality
    /// while leaving the reader unable to see what the equality is FOR.
    ///
    /// **Why the header hash is asserted too.** Peak height and header hash are written by one
    /// call (`set_peak`), so a fix that guarded only the height would leave the hash a
    /// peer-controlled value attached to an operator-established height — a worse state than
    /// either alone.
    #[tokio::test]
    async fn a_discovered_peer_coin_state_update_changes_no_sync_state_at_all() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        let before = db.sync_state().await.unwrap();
        let events = EventBus::default();
        let subscribed = subscribed_owned();

        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: u32::MAX,
                fork_height: u32::MAX - 1,
                peak_hash: Bytes32::new([7; 32]),
                // A coin at the SUBSCRIBED hash, which an authoritative session WOULD write:
                // the subscription filter is no defence against the peer we handed the set to.
                items: vec![state(coin(1, OWNED, 999), Some(6_000_001), None)],
            },
            &events,
            &mut discovered(&subscribed),
        )
        .await
        .expect("a dropped frame is not an error: the session stays up for its liveness");

        let after = db.sync_state().await.unwrap();
        assert_eq!(
            after.peak_height,
            Some(6_000_000),
            "a discovered peer must not move the peak, in EITHER direction"
        );
        assert_eq!(
            after.header_hash, before.header_hash,
            "nor the header hash the peak was established with"
        );
        assert_eq!(
            after.initial_sync_complete, before.initial_sync_complete,
            "nor the routing gate"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "nor write coins, even at a subscribed hash"
        );
    }

    /// **Proves (F1c):** the same refusal on the OTHER frame that carries a height.
    /// `new_peak_wallet` needs no subscription and no coin state, so it is the cheapest frame on
    /// the wire for a discovered peer to lie in — a guard placed only in
    /// [`handle_coin_state_update`] would leave this path wide open while every
    /// `coin_state_update` test stayed green.
    ///
    /// **The honest control in the same run.** An OPERATOR peer's `new_peak_wallet` at an
    /// ordinary height is delivered over the identical loop, and must still land. Without it
    /// this test is satisfied by a `run_update_loop` that ignores `new_peak_wallet` entirely.
    #[tokio::test]
    async fn a_discovered_peer_new_peak_wallet_is_dropped_while_an_operators_still_lands() {
        for (authority, claimed, expected) in [
            (WriteAuthority::Discovered, u32::MAX, 6_000_000u32),
            (WriteAuthority::Operator, 6_000_010, 6_000_010),
        ] {
            let db = WalletDb::open_in_memory().await.unwrap();
            db.set_peak(6_000_000, "aa").await.unwrap();
            let events = EventBus::default();
            let subscribed = subscribed_owned();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tx.send(new_peak_message(claimed)).await.unwrap();
            drop(tx); // closing the channel is how the loop returns

            run_update_loop(
                &db,
                rx,
                &events,
                None,
                &mut SessionState::with_authority(&subscribed, authority),
            )
            .await
            .unwrap();

            assert_eq!(
                db.sync_state().await.unwrap().peak_height,
                Some(expected),
                "{authority:?} peer claiming height {claimed}"
            );
        }
    }

    /// **Proves (F1c):** dropping a discovered peer's frames does not poison the replica against
    /// the honest peer that follows.
    ///
    /// This is the property the *previous* round's monotonic rule destroyed: once a hostile
    /// height landed, every truthful correction below it was refused, and on a default install
    /// nothing could ever lower it again. Here the hostile frame arrives FIRST, and the operator
    /// session that follows must still establish an ordinary height BELOW `u32::MAX` — which a
    /// never-retreats implementation cannot do.
    #[tokio::test]
    async fn an_honest_operator_correction_still_lands_after_a_hostile_discovered_frame() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        let events = EventBus::default();
        let subscribed = subscribed_owned();

        let hostile = CoinStateUpdate {
            height: u32::MAX,
            fork_height: u32::MAX - 1,
            peak_hash: Bytes32::new([7; 32]),
            items: vec![],
        };
        handle_coin_state_update(&db, &hostile, &events, &mut discovered(&subscribed))
            .await
            .unwrap();

        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: 6_000_100,
                fork_height: 6_000_099,
                peak_hash: Bytes32::new([9; 32]),
                items: vec![],
            },
            &events,
            &mut operator(&subscribed),
        )
        .await
        .expect("the honest peer's correction must be accepted");

        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(6_000_100),
            "the honest height is not fenced out by anything the hostile frame left behind"
        );
    }

    /// **Proves (F5, both sides of the bound):** the per-frame [`MAX_REORG_DEPTH`] bounds ONE
    /// frame; [`MAX_SESSION_ROLLBACK`] bounds the SEQUENCE, and a session that walks the peak
    /// down past it is dropped.
    ///
    /// Each frame here is individually legal - 64 blocks, half the per-frame bound - so a
    /// depth-only defence accepts every one of them forever. The bound is pinned from BOTH
    /// sides in one run: two frames spend exactly 128 and must SUCCEED, and the third must fail.
    #[tokio::test]
    async fn repeated_legal_rollbacks_exhaust_the_sessions_cumulative_budget() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        let events = EventBus::default();
        let subscribed = subscribed_owned();
        let mut session = operator(&subscribed);

        let mut peak = 6_000_000u32;
        for step in 1..=2 {
            peak -= 64;
            handle_coin_state_update(
                &db,
                &CoinStateUpdate {
                    height: peak,
                    fork_height: peak,
                    peak_hash: Bytes32::new([7; 32]),
                    items: vec![],
                },
                &events,
                &mut session,
            )
            .await
            .unwrap_or_else(|e| panic!("frame {step} spends within the bound, got {e:?}"));
        }

        let err = handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: peak - 1,
                fork_height: peak - 1,
                peak_hash: Bytes32::new([7; 32]),
                items: vec![],
            },
            &events,
            &mut session,
        )
        .await
        .expect_err("the frame that crosses the cumulative bound must drop the session");

        assert!(
            matches!(
                err,
                SyncError::RollbackBudgetExhausted {
                    spent: 129,
                    max: MAX_SESSION_ROLLBACK
                }
            ),
            "got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // The catch-up bounds (F4)
    // -----------------------------------------------------------------------

    /// **Proves (F4, both sides of both bounds):** [`CatchUpBudget`] admits exactly
    /// [`MAX_CATCH_UP_BATCHES`] batches and [`MAX_CATCH_UP_COINS`] rows, and refuses one more of
    /// either.
    ///
    /// The bounds are pinned here rather than by driving 250,000 rows through SQLite, because a
    /// bound tested only from the side that fails confirms only itself - and the at-bound case
    /// is the half that keeps a legitimate heavy wallet syncing.
    #[test]
    fn the_catch_up_budget_admits_exactly_its_bound_and_refuses_one_more() {
        let mut batches = CatchUpBudget::new();
        for i in 1..=MAX_CATCH_UP_BATCHES {
            batches
                .charge(0)
                .unwrap_or_else(|e| panic!("batch {i} is within the bound, got {e:?}"));
        }
        assert!(
            matches!(
                batches.charge(0),
                Err(SyncError::CatchUpTooLong {
                    max: MAX_CATCH_UP_BATCHES
                })
            ),
            "one batch past the bound must be refused"
        );

        let mut coins = CatchUpBudget::new();
        coins.charge(MAX_CATCH_UP_COINS).expect("at the row bound");
        assert!(
            matches!(
                coins.charge(1),
                Err(SyncError::CatchUpTooLarge {
                    max: MAX_CATCH_UP_COINS
                })
            ),
            "one row past the bound must be refused"
        );
    }

    /// A peer that answers `is_finished: false` at a CONSTANT height forever - the auditor's
    /// unbounded catch-up loop, which ran 2,001 round trips and grew `wallet.sqlite` on each.
    ///
    /// It counts its calls so the test can assert the loop actually STOPPED, rather than
    /// inferring it from an error that a peer erroring out on its own would also produce.
    struct NeverAdvances {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl PuzzleStateSource for NeverAdvances {
        async fn request_puzzle_state(
            &self,
            _puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(RespondPuzzleState {
                puzzle_hashes: vec![],
                coin_states: vec![state(coin(1, OWNED, 1), Some(10), None)],
                height: 6_000_000,
                header_hash: Bytes32::new([9; 32]),
                is_finished: false,
            })
        }
    }

    /// **Proves (F4):** a catch-up whose batches never advance is refused in a handful of round
    /// trips, not 2,001.
    #[tokio::test]
    async fn a_catch_up_that_never_advances_is_refused_after_a_couple_of_round_trips() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();
        let peer = NeverAdvances {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let err = initial_sync_with_authority(
            &peer,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            WriteAuthority::Operator,
            &DerivedCats::default(),
        )
        .await
        .expect_err("a non-advancing catch-up must be refused");

        assert!(
            matches!(err, SyncError::CatchUpNotAdvancing { .. }),
            "got {err:?}"
        );
        assert_eq!(
            peer.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the loop must stop as soon as a batch fails to advance"
        );
        assert!(
            !db.is_synced().await.unwrap(),
            "an abandoned catch-up leaves the replica unauthoritative"
        );
    }

    /// **Proves (#407):** with a [`CatAttributor`], the update loop runs the attribution pass
    /// after applying a coin state — fetching the candidate coin's parent spend so a synced
    /// CAT can be attributed. (The full uncurry→`get_cats` path is proven in `sage::rpc`.)
    #[tokio::test]
    async fn run_update_loop_runs_attribution_when_attributor_present() {
        use crate::sage::singleton::{LineageAnswer, LineageSource};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingLineage {
            hits: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl LineageSource for CountingLineage {
            async fn parent_spend(
                &self,
                _parent_coin_id: &str,
                _spent_height: u32,
            ) -> crate::sage::Result<LineageAnswer> {
                self.hits.fetch_add(1, Ordering::SeqCst);
                Ok(LineageAnswer::Absent)
            }
        }

        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(10, "aa").await.unwrap();
        let events = EventBus::with_capacity(8);
        let (tx, receiver) = tokio::sync::mpsc::channel::<Message>(4);
        // A candidate coin (its puzzle hash is not a wallet plain p2 hash) → attribution
        // fetches its parent spend.
        let update = CoinStateUpdate {
            height: 11,
            fork_height: 10,
            peak_hash: Bytes32::new([2; 32]),
            items: vec![state(coin(3, 9, 42), Some(11), None)],
        };
        let msg = Message {
            msg_type: ProtocolMessageTypes::CoinStateUpdate,
            id: None,
            data: chia_traits::Streamable::to_bytes(&update).unwrap().into(),
        };
        tx.send(msg).await.unwrap();
        drop(tx);

        let hits = Arc::new(AtomicUsize::new(0));
        let lineage = CountingLineage { hits: hits.clone() };
        let plain = HashSet::new();
        let attributor = CatAttributor {
            lineage: &lineage,
            prefix: "xch",
            plain_puzzle_hashes: &plain,
        };
        run_update_loop(
            &db,
            receiver,
            &events,
            Some(&attributor),
            &mut operator(&subscribed_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "attributor fetched the candidate coin's parent spend"
        );
    }

    /// **Proves (dig-node#546):** a $DIG arrival attributed WITHIN a frame is announced by the
    /// end of that SAME frame — it must not wait for a second `CoinStateUpdate` that may never
    /// arrive.
    ///
    /// # The bug, and why the fixture must drive `run_update_loop` itself
    ///
    /// `handle_coin_state_update` runs `record_arrivals` **before** the attribution pass promotes
    /// a staged CAT into `coins` — that ordering is #479/#480's own fix (see
    /// `a_cat_promoted_after_the_watermark_advanced_is_still_announced` in `db.rs`), so the hold
    /// `promote_cat_admission` leaves in `arrival_pending` is only ever examined by the NEXT
    /// frame's `record_arrivals` call. A wallet that receives once and then falls quiet never gets
    /// a second frame, so the row waits forever — confirmed live on mainnet in #546 across ~50
    /// minutes, two restarts, and a second watched address.
    ///
    /// A test that manually called `record_arrivals` again after promoting would prove only that
    /// the DB layer is idempotent — already covered by the #479 test above — and it would pass
    /// identically on the UNFIXED code, because the manual call substitutes for the very
    /// production behaviour under test instead of exercising it. So this drives the real glue,
    /// `run_update_loop`, over exactly ONE inbound message, with a REAL CAT parent spend so
    /// attribution genuinely promotes it, and the test itself never calls `record_arrivals`.
    #[tokio::test]
    async fn a_cat_attributed_within_one_frame_is_announced_in_that_same_frame() {
        use crate::sage::cat_discovery::tests::real_cat;
        use crate::sage::singleton::LineageAnswer;

        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        // Already synced with nothing news yet — exactly the "receives once, then goes quiet"
        // wallet #546 reports: one completed catch-up, then a single live arrival.
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 9, "hh", &[]).unwrap())
            .await
            .unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);

        // The ONE frame: the $DIG coin lands at its derived outer hash, above the baseline, and
        // nothing else ever arrives after it.
        let update = CoinStateUpdate {
            height: 10,
            fork_height: 9,
            peak_hash: Bytes32::new([2; 32]),
            items: vec![state(f.child, Some(10), None)],
        };
        let events = EventBus::with_capacity(8);
        let (tx, receiver) = tokio::sync::mpsc::channel::<Message>(4);
        tx.send(Message {
            msg_type: ProtocolMessageTypes::CoinStateUpdate,
            id: None,
            data: chia_traits::Streamable::to_bytes(&update).unwrap().into(),
        })
        .await
        .unwrap();
        drop(tx);

        /// A [`LineageSource`] that answers `Found` for exactly one parent, real CLVM bytes and
        /// all — a fake reconstruction cannot exist, since `singleton::reconstruct` uncurries the
        /// actual puzzle/solution rather than trusting anything this double asserts.
        struct FixedLineage {
            parent_id: String,
            spend: crate::sage::singleton::ParentSpend,
        }
        #[async_trait::async_trait]
        impl LineageSource for FixedLineage {
            async fn parent_spend(
                &self,
                parent_coin_id: &str,
                _spent_height: u32,
            ) -> crate::sage::Result<LineageAnswer> {
                if parent_coin_id.eq_ignore_ascii_case(&self.parent_id) {
                    Ok(LineageAnswer::Found(Box::new(self.spend.clone())))
                } else {
                    Ok(LineageAnswer::Unavailable)
                }
            }
        }
        let lineage = FixedLineage {
            parent_id: hex::encode(f.child.parent_coin_info),
            spend: f.parent,
        };
        let plain = HashSet::new();
        let attributor = CatAttributor {
            lineage: &lineage,
            prefix: "xch",
            plain_puzzle_hashes: &plain,
        };
        let subscribed = subscribed_owned();
        let mut session = operator(&subscribed).following_derived_cats(&derived);

        run_update_loop(&db, receiver, &events, Some(&attributor), &mut session)
            .await
            .unwrap();

        let ids: Vec<String> = db
            .arrivals_since(0, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.coin_id)
            .collect();
        assert_eq!(
            ids,
            vec![hex::encode(f.child.coin_id())],
            "a CAT attributed within this frame must be announced by the end of the SAME frame, \
             not left waiting in arrival_pending for a frame that may never come"
        );
    }

    /// **Proves (dig-node#383):** a frame the node REFUSED schedules no attribution pass.
    ///
    /// # The fixture varies one actor and keeps an honest control
    ///
    /// Two runs over the same replica, the same seeded candidate row and the same frame. Only the
    /// session's trust differs. An operator session MUST run the pass — that is the control, and
    /// without it "zero reads" would be satisfied by an attributor that was simply never wired, or
    /// by a fixture that presented no candidate row to read. A discovered session must not, because
    /// its frame is dropped before any database write.
    ///
    /// The frame is EMPTY on purpose. An empty, refused frame is the cheapest thing on the wire, so
    /// a peer that gets a whole-replica pass for it has an amplifier however the pass is bounded.
    #[tokio::test]
    async fn a_refused_frame_schedules_no_attribution_pass() {
        use crate::sage::singleton::{LineageAnswer, LineageSource};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingLineage {
            hits: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl LineageSource for CountingLineage {
            async fn parent_spend(
                &self,
                _parent_coin_id: &str,
                _spent_height: u32,
            ) -> crate::sage::Result<LineageAnswer> {
                self.hits.fetch_add(1, Ordering::SeqCst);
                Ok(LineageAnswer::Absent)
            }
        }

        /// Run one empty `coin_state_update` through the production loop and report how many
        /// parent-spend reads the seeded candidate row cost.
        async fn reads_for_one_empty_frame(authoritative: bool) -> usize {
            let db = WalletDb::open_in_memory().await.unwrap();
            db.set_peak(10, "aa").await.unwrap();
            // One unattributed, unspent, confirmed coin at an unsubscribed hash: a candidate the
            // pass will want to read the moment it runs.
            db.upsert_coins(&[CoinRow {
                coin_id: hex::encode([9u8; 32]),
                parent_coin_info: hex::encode([8u8; 32]),
                puzzle_hash: hex::encode([7u8; 32]),
                amount: "1".into(),
                created_height: Some(5),
                spent_height: None,
                asset_id: None,
                hint: None,
                created_timestamp: None,
                spent_timestamp: None,
            }])
            .await
            .unwrap();

            let events = EventBus::with_capacity(8);
            let (tx, receiver) = tokio::sync::mpsc::channel::<Message>(4);
            let update = CoinStateUpdate {
                height: 11,
                fork_height: 10,
                peak_hash: Bytes32::new([2; 32]),
                items: vec![],
            };
            tx.send(Message {
                msg_type: ProtocolMessageTypes::CoinStateUpdate,
                id: None,
                data: chia_traits::Streamable::to_bytes(&update).unwrap().into(),
            })
            .await
            .unwrap();
            drop(tx);

            let hits = Arc::new(AtomicUsize::new(0));
            let lineage = CountingLineage { hits: hits.clone() };
            let plain = HashSet::new();
            let attributor = CatAttributor {
                lineage: &lineage,
                prefix: "xch",
                plain_puzzle_hashes: &plain,
            };
            let subscribed = subscribed_owned();
            let mut session = if authoritative {
                operator(&subscribed)
            } else {
                discovered(&subscribed)
            };
            run_update_loop(&db, receiver, &events, Some(&attributor), &mut session)
                .await
                .unwrap();
            hits.load(Ordering::SeqCst)
        }

        assert_eq!(
            reads_for_one_empty_frame(true).await,
            1,
            concat!(
                "control: an APPLIED frame runs the pass, so the fixture really does ",
                "present a candidate row that costs a read"
            )
        );
        assert_eq!(
            reads_for_one_empty_frame(false).await,
            0,
            concat!(
                "a frame dropped before any database write must schedule no work at all; ",
                "running the pass after it lets a peer buy a whole-replica scan for an ",
                "empty frame it already knows will be refused"
            )
        );
    }

    // ---------------------------------------------------------------------------------------
    // A reset that lands MID-CATCH-UP must not be overwritten by the catch-up it interrupted
    // (dig-node#454). The reset transaction is atomic; the catch-up's two writes are not
    // serialised against it, so the in-flight catch-up's terminal statement used to re-set
    // `initial_sync_complete` over the table the reset had just emptied.
    // ---------------------------------------------------------------------------------------

    /// A peer that answers one ordinary batch, then — standing in for the user pressing reset
    /// while that batch is being applied — RESETS the coin database before answering the
    /// terminal batch.
    ///
    /// The reset is driven from inside the peer double because that is the only place in this
    /// test that runs BETWEEN the catch-up's two writes. `carries_coins` selects which variant
    /// the terminal answer produces: an empty one (the zero-balance lie) or a single coin (the
    /// partial-set lie, which reads as a plausible understated balance and is the one a user
    /// would actually hit).
    struct ResetsBeforeFinishing {
        db: WalletDb,
        calls: std::sync::atomic::AtomicUsize,
        carries_coins: bool,
    }

    #[async_trait::async_trait]
    impl PuzzleStateSource for ResetsBeforeFinishing {
        async fn request_puzzle_state(
            &self,
            puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                // An ordinary, non-terminal batch that really transfers state: the coin below is
                // what the reset then deletes, so the fixture has something to lose.
                return Ok(RespondPuzzleState {
                    puzzle_hashes,
                    coin_states: vec![state(coin(1, OWNED, 700), Some(50), None)],
                    height: 100,
                    header_hash: Bytes32::new([9; 32]),
                    is_finished: false,
                });
            }
            self.db
                .reset_chain_cache(0)
                .await
                .expect("the reset itself succeeds")
                .expect("no spend is in flight, so it cannot refuse");
            Ok(RespondPuzzleState {
                puzzle_hashes,
                coin_states: if self.carries_coins {
                    vec![state(coin(2, OWNED, 300), Some(60), None)]
                } else {
                    vec![]
                },
                height: 6_000_000,
                header_hash: Bytes32::new([9; 32]),
                is_finished: true,
            })
        }
    }

    async fn catch_up_interrupted_by_a_reset(
        carries_coins: bool,
    ) -> (WalletDb, Result<(), SyncError>) {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();
        let outcome = initial_sync_with_authority(
            &ResetsBeforeFinishing {
                db: db.clone(),
                calls: std::sync::atomic::AtomicUsize::new(0),
                carries_coins,
            },
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([1; 32]),
            "1.2.3.4",
            &events,
            WriteAuthority::Operator,
            &DerivedCats::default(),
        )
        .await;
        (db, outcome)
    }

    /// **Proves (the money lie, zero variant):** a reset landing mid-catch-up leaves the coin
    /// table EMPTY, and the catch-up that was already running must not then declare that empty
    /// table authoritative — `balance 0, synced true` on a funded wallet.
    ///
    /// Asserted on the OBSERVABLE PAIR a caller reads, not on an internal counter: the pair is
    /// what lies, and a guard that moved elsewhere would still have to keep this pair honest.
    #[tokio::test]
    async fn a_reset_mid_catch_up_is_not_overwritten_into_an_empty_authoritative_replica() {
        let (db, outcome) = catch_up_interrupted_by_a_reset(false).await;

        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "the reset emptied the coins"
        );
        assert!(
            !db.is_synced().await.unwrap(),
            "an emptied replica reported as synced answers `balance 0, synced true` on a funded \
             wallet: reads route to the DB tier and find nothing"
        );
        assert!(
            matches!(outcome, Err(SyncError::ResetDuringCatchUp)),
            "the catch-up must report that its work was discarded so the supervisor runs a fresh \
             one, not return Ok over a replica it did not establish; got {outcome:?}"
        );
    }

    /// **Proves (the money lie, PARTIAL variant — the likelier one):** the reset lands after some
    /// of the replay has been applied, so the table holds a plausible-looking SUBSET. Reported as
    /// synced, that is an understated balance rather than an obvious zero, and far harder to
    /// notice.
    ///
    /// This second case exists because the zero variant alone cannot distinguish "the flag is
    /// refused" from "the flag happens to be false because nothing was written".
    #[tokio::test]
    async fn a_reset_mid_catch_up_is_not_overwritten_into_a_partial_authoritative_replica() {
        let (db, outcome) = catch_up_interrupted_by_a_reset(true).await;

        assert_eq!(
            db.balance(None).await.unwrap(),
            300,
            "control: the post-reset batch really did land, so the table holds a SUBSET of the \
             wallet's coins rather than nothing — this is the state that would read as an \
             understated balance"
        );
        assert!(
            !db.is_synced().await.unwrap(),
            "a partial coin set reported as synced is an understated balance presented as \
             complete"
        );
        assert!(
            matches!(outcome, Err(SyncError::ResetDuringCatchUp)),
            "got {outcome:?}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // The corroborated peak ceiling (dig_ecosystem#2851).
    // ---------------------------------------------------------------------------------------

    /// A peer that answers one batch and reports it is caught up at a height IT chooses — which
    /// is the whole point, because the terminal height is a value a hostile writer picks freely.
    struct FinishesAt(u32);

    #[async_trait::async_trait]
    impl PuzzleStateSource for FinishesAt {
        async fn request_puzzle_state(
            &self,
            _puzzle_hashes: Vec<Bytes32>,
            _previous_height: Option<u32>,
            _header_hash: Bytes32,
        ) -> Result<RespondPuzzleState, SyncError> {
            Ok(RespondPuzzleState {
                puzzle_hashes: vec![],
                coin_states: vec![],
                height: self.0,
                header_hash: Bytes32::new([9; 32]),
                is_finished: true,
            })
        }
    }

    /// Run a catch-up over a peer that finishes at `terminal`, for a session holding `authority`.
    async fn catch_up_finishing_at(
        db: &WalletDb,
        authority: WriteAuthority,
        terminal: u32,
    ) -> Result<(), SyncError> {
        let events = EventBus::default();
        initial_sync_with_authority(
            &FinishesAt(terminal),
            db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([1; 32]),
            "1.2.3.4",
            &events,
            authority,
            &DerivedCats::default(),
        )
        .await
    }

    /// **Proves (the named attack):** an elevated writer cannot claim `u32::MAX`.
    ///
    /// `peak_height` is what a caller divides into a confirmation count, so one accepted frame
    /// here reads as ~4.29e9 confirmations for a spend that never landed.
    #[tokio::test]
    async fn corroborated_writer_cannot_claim_u32_max() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(1000, "aa").await.unwrap();
        let subscribed = subscribed_owned();

        feed(
            &db,
            &mut corroborated(&subscribed, 1000),
            vec![new_peak_message(u32::MAX)],
        )
        .await
        .expect("one over-ceiling frame is dropped, not fatal");

        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(1000),
            "the replica peak must be left exactly where the quorum settled it"
        );
    }

    /// **Proves (the 3-strike shape, both halves):** the first two over-ceiling frames drop the
    /// FRAME only and write nothing, and the third retires the session.
    ///
    /// Both halves matter. Asserting only the error would be satisfied by a bound that kills the
    /// session on the FIRST frame, which NC-12 forbids — corroboration is a confidence gradient,
    /// and a single wildly-ahead claim can be a peer mid-reorg or mid-restart. Asserting only the
    /// tolerance would be satisfied by a bound that never ends the session at all.
    #[tokio::test]
    async fn three_over_ceiling_claims_retire_the_session() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(1000, "aa").await.unwrap();
        let subscribed = subscribed_owned();
        let mut session = corroborated(&subscribed, 1000);

        for frame in 1..=2 {
            feed(&db, &mut session, vec![new_peak_message(u32::MAX)])
                .await
                .unwrap_or_else(|e| panic!("frame {frame} must be tolerated, got {e}"));
            assert_eq!(
                db.sync_state().await.unwrap().peak_height,
                Some(1000),
                "frame {frame} must write nothing"
            );
        }

        let err = feed(&db, &mut session, vec![new_peak_message(u32::MAX)])
            .await
            .expect_err("the third must retire the session");
        assert!(
            matches!(err, SyncError::PeakAboveCeiling { claimed, .. } if claimed == u32::MAX),
            "got {err:?}"
        );
        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(1000),
            "and still write nothing on the way out"
        );
    }

    /// **Proves (both sides of the bound):** the ceiling admits exactly its limit and refuses one
    /// above it. A bound tested only from below can only confirm itself.
    #[tokio::test]
    async fn peak_ceiling_boundary() {
        let anchor = 6_000_000u32;
        let at_bound = anchor + peak_allowance(SESSION_MAX_LIFETIME);

        for (claimed, expected) in [(at_bound, at_bound), (at_bound + 1, anchor)] {
            let db = WalletDb::open_in_memory().await.unwrap();
            db.set_peak(anchor, "aa").await.unwrap();
            let subscribed = subscribed_owned();

            feed(
                &db,
                &mut corroborated(&subscribed, anchor),
                vec![new_peak_message(claimed)],
            )
            .await
            .unwrap();

            assert_eq!(
                db.sync_state().await.unwrap().peak_height,
                Some(expected),
                "a claim of {claimed} against a ceiling of {at_bound}"
            );
        }
    }

    /// **Proves (the reason this bound ships WITH the other two guards):** after a refused
    /// inflation, both guards added on this branch still work.
    ///
    /// This is the test the whole change exists for. An accepted `u32::MAX` does not merely
    /// misreport the peak — it permanently DISABLES both of them, and silently:
    /// [`FollowingEvidence`]'s `peers.saturating_sub(replica)` is `0` for ever, so the phase reports
    /// `Synced` however far behind the replica really is; and [`StallWatch`]'s
    /// `behind = peers > replica` is false for ever, so the stall clock never starts.
    ///
    /// So the fixture keeps an HONEST observer — peers genuinely 50 blocks ahead of a replica that
    /// is not moving — and asserts both guards still see it. With the bound removed the replica
    /// peak is `u32::MAX`, both go quiet, and both assertions below fail.
    #[tokio::test]
    async fn the_guards_still_function_after_a_refused_inflation() {
        let anchor = 1000u32;
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(anchor, "aa").await.unwrap();
        let subscribed = subscribed_owned();

        feed(
            &db,
            &mut corroborated(&subscribed, anchor),
            vec![new_peak_message(u32::MAX)],
        )
        .await
        .unwrap();

        let replica = db.sync_state().await.unwrap().peak_height;
        let peers = Some(anchor + 50);

        assert!(
            FollowingEvidence::measure(replica, peers).is_none(),
            "the phase must still be able to see a replica {replica:?} behind peers {peers:?}"
        );

        let t0 = std::time::Instant::now();
        let mut watch = StallWatch::default();
        assert_eq!(
            watch.observe(replica, peers, t0),
            StallVerdict::Following,
            "the first observation only starts the clock"
        );
        assert!(
            matches!(
                watch.observe(replica, peers, t0 + STALL_AFTER),
                StallVerdict::Stalled { .. }
            ),
            "the stall clock must still reach its deadline"
        );
    }

    /// **Proves (write site 2):** an over-ceiling catch-up TERMINAL is refused, and neither the
    /// routing gate nor the arrival baseline is armed over it.
    ///
    /// This site gets no three-strike tolerance, because the value arms `initial_sync_complete`
    /// AND the baseline in one statement — there is no benign reading of it.
    #[tokio::test]
    async fn catch_up_terminal_above_ceiling_never_arms_the_flag() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 6_000_000u32;

        let err = catch_up_finishing_at(
            &db,
            WriteAuthority::Corroborated(ceiling_at(anchor)),
            u32::MAX,
        )
        .await
        .expect_err("an over-ceiling terminal must end the session");

        assert!(
            matches!(err, SyncError::PeakAboveCeiling { .. }),
            "got {err:?}"
        );
        assert!(
            !db.sync_state().await.unwrap().initial_sync_complete,
            "the routing gate must not be armed over a refused terminal"
        );
        assert_eq!(
            db.arrival_baseline().await.unwrap(),
            None,
            "nor the arrival baseline"
        );
    }

    /// **Proves (the fresh-install case a delta cap would have broken):** a first catch-up from
    /// genesis, with NO replica peak at all, is accepted.
    ///
    /// An absolute anchor needs no `initial_sync_complete` discriminator to tell this apart from
    /// an attack — which matters, because that flag is attacker-clearable.
    #[tokio::test]
    async fn fresh_install_catch_up_from_genesis_is_accepted() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 9_142_918u32;
        assert_eq!(db.sync_state().await.unwrap().peak_height, None);

        catch_up_finishing_at(
            &db,
            WriteAuthority::Corroborated(ceiling_at(anchor)),
            anchor + 2,
        )
        .await
        .expect("a fresh install must still be able to catch up");

        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(anchor + 2));
    }

    /// **Proves (why a per-frame delta cap was rejected):** a replica 500,000 blocks behind
    /// catches up to the anchor in one step.
    ///
    /// A cap anchored on the replica's OWN peak cannot tell this from an inflation attack; an
    /// absolute one does not need to.
    #[tokio::test]
    async fn long_downtime_catch_up_is_accepted() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 6_000_000u32;
        db.set_peak(anchor - 500_000, "aa").await.unwrap();

        catch_up_finishing_at(
            &db,
            WriteAuthority::Corroborated(ceiling_at(anchor)),
            anchor,
        )
        .await
        .expect("a long-downtime catch-up must still be accepted");

        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(anchor));
    }

    /// **Proves (the tier difference, as behaviour rather than prose):** an OPERATOR session has
    /// no ceiling.
    ///
    /// The operator hand-configured that address and corroboration never runs on that path, so
    /// there is no independent anchor to build a ceiling from — and inventing one would
    /// second-guess an explicit configuration.
    #[tokio::test]
    async fn operator_session_has_no_ceiling() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 6_000_000u32;
        db.set_peak(anchor, "aa").await.unwrap();
        let subscribed = subscribed_owned();

        feed(
            &db,
            &mut operator(&subscribed),
            vec![new_peak_message(anchor + 1_000_000)],
        )
        .await
        .unwrap();

        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(anchor + 1_000_000)
        );
    }

    /// **Proves (the regression guard for the discriminator deliberately NOT used):** driving a
    /// reorg — which clears `initial_sync_complete` — does not widen the ceiling.
    ///
    /// A delta-cap design would have keyed on that flag, and this is the frame that clears it, so
    /// a writer could re-open the window on demand by driving one reorg.
    #[tokio::test]
    async fn a_reorg_that_clears_initial_sync_complete_does_not_widen_the_ceiling() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 1000u32;
        db.set_peak(anchor, "aa").await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let events = EventBus::default();
        let subscribed = subscribed_owned();
        let mut session = corroborated(&subscribed, anchor);

        handle_coin_state_update(
            &db,
            &CoinStateUpdate {
                height: anchor - 10,
                fork_height: anchor - 10,
                peak_hash: Bytes32::new([7; 32]),
                items: vec![],
            },
            &events,
            &mut session,
        )
        .await
        .expect("an ordinary shallow reorg is accepted");
        assert!(
            !db.sync_state().await.unwrap().initial_sync_complete,
            "the reorg must have cleared the flag, or this test guards nothing"
        );

        feed(&db, &mut session, vec![new_peak_message(u32::MAX)])
            .await
            .unwrap();

        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(anchor - 10),
            "the ceiling is anchored on the quorum, not on the flag the writer just cleared"
        );
    }

    // ---- write site 3: the coin-state update (dig_ecosystem#2851, F1) -------

    /// A `coin_state_update` push, exactly as it arrives on the wire.
    fn coin_state_update(height: u32, fork_height: u32, items: Vec<CoinState>) -> CoinStateUpdate {
        CoinStateUpdate {
            height,
            fork_height,
            peak_hash: Bytes32::new([7; 32]),
            items,
        }
    }

    /// Push one `coin_state_update` through the production handler.
    async fn push(
        db: &WalletDb,
        session: &mut SessionState<'_>,
        update: CoinStateUpdate,
    ) -> Result<FrameApplied, SyncError> {
        handle_coin_state_update(db, &update, &EventBus::default(), session).await
    }

    /// **Proves (the named attack, by execution):** a `coin_state_update` cannot inflate the peak
    /// past the session's ceiling either.
    ///
    /// The frame is chosen to slip every OTHER guard on this branch simultaneously:
    /// `fork_height == peak` means no rollback and no backwards move, so
    /// `initial_sync_complete` is never cleared, and the height lands straight in the value a
    /// caller divides into a confirmation count — ~4.29e9 confirmations for a spend that never
    /// landed.
    #[tokio::test]
    async fn corroborated_coin_state_update_cannot_inflate_the_peak() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 1000u32;
        db.set_peak(anchor, "aa").await.unwrap();
        let subscribed = subscribed_owned();

        push(
            &db,
            &mut corroborated(&subscribed, anchor),
            coin_state_update(u32::MAX, anchor, vec![]),
        )
        .await
        .expect("one over-ceiling frame is dropped, not fatal");

        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(anchor),
            "the replica peak must be left exactly where the quorum settled it"
        );
    }

    /// **Proves (why the third site mattered):** the two liveness guards survive the refusal.
    ///
    /// An accepted `u32::MAX` does not merely misreport the peak — it permanently silences both
    /// guards, and does so through THIS frame type just as through `new_peak_wallet`. The fixture
    /// keeps an honest observer (peers genuinely 50 blocks ahead of a replica that is not moving)
    /// so a regression is visible rather than merely unasserted.
    #[tokio::test]
    async fn the_guards_still_function_after_a_refused_coin_state_inflation() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 1000u32;
        db.set_peak(anchor, "aa").await.unwrap();
        let subscribed = subscribed_owned();

        push(
            &db,
            &mut corroborated(&subscribed, anchor),
            coin_state_update(u32::MAX, anchor, vec![]),
        )
        .await
        .unwrap();

        let replica = db.sync_state().await.unwrap().peak_height;
        let peers = Some(anchor + 50);

        assert!(
            FollowingEvidence::measure(replica, peers).is_none(),
            "the phase must still see a replica {replica:?} behind peers {peers:?}"
        );

        let t0 = std::time::Instant::now();
        let mut watch = StallWatch::default();
        assert_eq!(
            watch.observe(replica, peers, t0),
            StallVerdict::Following,
            "the first observation only starts the clock"
        );
        assert!(
            matches!(
                watch.observe(replica, peers, t0 + STALL_AFTER),
                StallVerdict::Stalled { .. }
            ),
            "the stall clock must still reach its deadline"
        );
    }

    /// **Proves (the strike counter reaches this site too):** the first two over-ceiling
    /// `coin_state_update`s drop the FRAME only, and the third retires the session.
    ///
    /// Without the counter here an attacker re-inflates on every frame for ever, because
    /// [`MAX_REFUSED_PEAK_CLAIMS`] never retires a session that is never charged.
    #[tokio::test]
    async fn three_over_ceiling_coin_state_updates_retire_the_session() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 1000u32;
        db.set_peak(anchor, "aa").await.unwrap();
        let subscribed = subscribed_owned();
        let mut session = corroborated(&subscribed, anchor);

        for frame in 1..=2 {
            push(
                &db,
                &mut session,
                coin_state_update(u32::MAX, anchor, vec![]),
            )
            .await
            .unwrap_or_else(|e| panic!("frame {frame} must be tolerated, got {e}"));
            assert_eq!(
                db.sync_state().await.unwrap().peak_height,
                Some(anchor),
                "frame {frame} must write nothing"
            );
        }

        let err = push(
            &db,
            &mut session,
            coin_state_update(u32::MAX, anchor, vec![]),
        )
        .await
        .expect_err("the third must retire the session");
        assert!(
            matches!(err, SyncError::PeakAboveCeiling { claimed, .. } if claimed == u32::MAX),
            "got {err:?}"
        );
    }

    /// **Proves (the PLACEMENT, not merely the outcome):** the refusal happens BEFORE the frame's
    /// destructive half runs.
    ///
    /// The fixture pairs the inflated height with a genuine reorg (`fork_height` ten blocks below
    /// the peak) and a coin the wallet owns. A guard placed at the write — which satisfies "the
    /// peak is unchanged" identically — would still have rolled the replica back, deleted the coin
    /// and cleared the routing gate on the strength of a height it was about to reject. So the
    /// assertions are on the three things a late guard would have already destroyed.
    #[tokio::test]
    async fn a_refused_coin_state_update_leaves_the_replica_untouched() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 1000u32;
        apply_coin_states(
            &db,
            &[state(coin(1, OWNED, 5_000), Some(anchor - 5), None)],
            &subscribed_owned(),
            &DerivedCats::default(),
        )
        .await
        .unwrap();
        db.set_peak(anchor, "aa").await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let subscribed = subscribed_owned();

        push(
            &db,
            &mut corroborated(&subscribed, anchor),
            coin_state_update(u32::MAX, anchor - 10, vec![]),
        )
        .await
        .expect("one over-ceiling frame is dropped, not fatal");

        let sync_state = db.sync_state().await.unwrap();
        assert_eq!(sync_state.peak_height, Some(anchor), "no peak was written");
        assert!(
            sync_state.initial_sync_complete,
            "a frame refused before it acted must not clear the routing gate"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            5_000,
            "nor roll the replica back over a height it then rejected"
        );
    }

    /// **Proves (the negative control):** an in-ceiling `coin_state_update` still advances the
    /// peak and writes its coins, so the fix is not "refuse everything".
    #[tokio::test]
    async fn an_in_ceiling_coin_state_update_still_writes_peak_and_coins() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let anchor = 1000u32;
        db.set_peak(anchor, "aa").await.unwrap();
        let subscribed = subscribed_owned();
        let claimed = anchor + peak_allowance(SESSION_MAX_LIFETIME);

        push(
            &db,
            &mut corroborated(&subscribed, anchor),
            coin_state_update(
                claimed,
                anchor,
                vec![state(coin(1, OWNED, 4_200), Some(claimed), None)],
            ),
        )
        .await
        .expect("a claim at the ceiling is admitted");

        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(claimed));
        assert_eq!(db.balance(None).await.unwrap(), 4_200);
    }

    /// **Proves (the hidden coupling):** the allowance is DERIVED from the session lifetime.
    ///
    /// [`SESSION_MAX_LIFETIME`]'s own doc calls its value an overridable operating assumption that
    /// may move UP, and a hardcoded ceiling would silently become too tight when it does.
    #[test]
    fn peak_allowance_tracks_the_session_lifetime() {
        assert_eq!(
            peak_allowance(SESSION_MAX_LIFETIME),
            194,
            "128 blocks of reorg allowance plus 66 of chain progress at the shipped lifetime"
        );
        assert!(
            peak_allowance(Duration::from_secs(3600)) > peak_allowance(SESSION_MAX_LIFETIME),
            "a longer session must be allowed to gain more chain"
        );
    }
}
