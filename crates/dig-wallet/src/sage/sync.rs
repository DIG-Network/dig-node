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

use chia::protocol::{
    Coin, CoinState, CoinStateFilters, CoinStateUpdate, Message, NewPeakWallet,
    ProtocolMessageTypes, RespondPuzzleState,
};
use chia_protocol::Bytes32;
use chia_wallet_sdk::client::Peer;

use super::db::{CatchUpReplay, CoinRow, WalletDb};
use super::events::{EventBus, SyncEvent};
use super::singleton::{self, LineageSource};

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
    /// [`initial_sync`] was asked to catch up over an EMPTY puzzle-hash set.
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

/// The most catch-up round trips one [`initial_sync_with`] may make.
///
/// The loop continues while the peer answers `is_finished: false`, and the peer chooses that
/// bit. Combined with the strict height-monotonicity check below this is belt and braces: the
/// height check alone bounds the loop by the chain's length, which is millions. A real
/// catch-up needs a handful of batches even for a heavily-used wallet.
pub const MAX_CATCH_UP_BATCHES: u32 = 1_024;

/// The most coin states one [`initial_sync_with`] may write, summed across its batches.
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

/// Everything one peer session carries across the frames it handles: what it subscribed, how
/// far its peer is trusted, and how much of its rollback allowance it has spent.
///
/// It exists because two of this module's defences are per-SESSION rather than per-frame — the
/// trust boundary ([`PeerTrust`]) and the cumulative rollback bound ([`RollbackBudget`]) — and a
/// free function handed one frame at a time cannot enforce either. [`run_update_loop`] owns one
/// and lends it to every [`handle_coin_state_update`] call.
pub struct SessionState<'a> {
    /// The puzzle hashes this session subscribed. Empty when the session subscribes nothing.
    pub subscribed: &'a SubscribedHashes,
    /// How far this session's peer is trusted.
    pub trust: PeerTrust,
    /// The session's remaining allowance for walking the peak backwards.
    pub rollback: RollbackBudget,
}

impl<'a> SessionState<'a> {
    /// A session over `subscribed` whose peer is trusted to the degree `trust` says.
    pub fn new(subscribed: &'a SubscribedHashes, trust: PeerTrust) -> Self {
        Self {
            subscribed,
            trust,
            rollback: RollbackBudget::new(),
        }
    }
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

/// The running cost of one catch-up, bounded by [`MAX_CATCH_UP_BATCHES`] and
/// [`MAX_CATCH_UP_COINS`].
///
/// Split out of [`initial_sync_with`] as a small value with no I/O so both bounds can be pinned
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
pub async fn apply_coin_states(
    db: &WalletDb,
    states: &[CoinState],
    subscribed: &SubscribedHashes,
) -> Result<(), SyncError> {
    let rows: Vec<CoinRow> = states
        .iter()
        .filter(|s| subscribed.contains(&s.coin.puzzle_hash))
        .map(coin_state_to_row)
        .collect();
    if rows.len() != states.len() {
        tracing::warn!(
            dropped = states.len() - rows.len(),
            "wallet sync: peer pushed coin states outside the subscribed puzzle-hash set"
        );
    }
    db.upsert_coins(&rows).await?;
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
    /// The parent-spend source (coinset/peer point-read) uncurrying reads through.
    pub lineage: &'a dyn LineageSource,
    /// The address bech32m prefix for any reconstructed NFT/DID addresses.
    pub prefix: &'a str,
    /// The wallet's own plain p2 puzzle hashes (hex) — ordinary XCH coins at these are skipped.
    pub plain_puzzle_hashes: &'a HashSet<String>,
}

impl CatAttributor<'_> {
    /// Attribute every not-yet-attributed coin currently in `db` (idempotent: already-spent
    /// or already-attributed coins are skipped by [`singleton::reconstruct_coins`]).
    pub async fn attribute(&self, db: &WalletDb) -> Result<(), SyncError> {
        singleton::reconstruct_all(db, self.lineage, self.prefix, self.plain_puzzle_hashes)
            .await
            .map(|_| ())
            .map_err(|e| SyncError::Attribution(e.to_string()))
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
/// When `session.trust` is [`PeerTrust::Discovered`] this returns without touching the database:
/// no rollback, no coin write, no routing flag, and no peak (see [`PeerTrust`] for why the peak
/// is not the harmless half). Dropping the frame is not an error — the session stays up, because
/// the peer still counts toward `subscription_peer_count`.
pub async fn handle_coin_state_update(
    db: &WalletDb,
    update: &CoinStateUpdate,
    events: &EventBus,
    session: &mut SessionState<'_>,
) -> Result<(), SyncError> {
    if !session.trust.is_authoritative() {
        tracing::debug!(
            claimed_height = update.height,
            "wallet sync: dropping a coin_state_update from a discovered peer"
        );
        return Ok(());
    }
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
        db.set_initial_sync_complete(false).await?;
    }
    apply_coin_states(db, &update.items, session.subscribed).await?;
    db.set_peak(update.height, &hex::encode(update.peak_hash))
        .await?;
    // Incoming-funds arrivals (dig_ecosystem#2548), recorded AFTER the batch has committed and
    // the peak has advanced — never during the write. A parent and its change coin arrive in the
    // same frame in whatever order the peer chose, so deciding "did we create this coin ourselves?"
    // inside the write would race the batch and read the user's own change as a payment.
    //
    // The recorder is fail-closed on its own: with no baseline (no completed catch-up) it records
    // nothing, so the history this same function replays on every reconnect is never announced.
    //
    // A recorder failure is LOGGED, not propagated. Chain sync is the critical path and a
    // notification ledger is not: returning `?` here would drop a live peer session over a
    // NOTIFICATION write, which is a strictly worse outcome than a delayed toast. Nothing is lost
    // by continuing — the ledger insert and the baseline advance share one transaction, so a failed
    // pass leaves the watermark where it was and the next update re-examines the same coins.
    let watched: Vec<String> = session.subscribed.iter().map(hex::encode).collect();
    if let Err(e) = db.record_arrivals(&watched, update.height).await {
        tracing::warn!(
            error = %e,
            height = update.height,
            "wallet sync: recording incoming-funds arrivals failed; retrying on the next update"
        );
    }
    events.publish(SyncEvent::CoinState);
    Ok(())
}

/// Perform the initial puzzle-state catch-up: subscribe the wallet's puzzle hashes and
/// apply the returned coin states, batching through `RespondPuzzleState.next` until the
/// peer reports it is caught up. Marks the DB initial-sync-complete so
/// [`crate::sage::routing`] flips reads from the fallback to the DB.
///
/// Publishes the sync lifecycle on `events` (design A.9): [`SyncEvent::Start`] once (the
/// caller supplies `peer_ip` — whatever address it dialed to obtain `peer`),
/// [`SyncEvent::Subscribed`] after the first successful puzzle-state response, and
/// [`SyncEvent::PuzzleBatchSynced`] once per batch applied.
pub async fn initial_sync(
    peer: &Peer,
    db: &WalletDb,
    puzzle_hashes: Vec<Bytes32>,
    genesis_challenge: Bytes32,
    peer_ip: &str,
    events: &EventBus,
    trust: PeerTrust,
) -> Result<(), SyncError> {
    initial_sync_with(
        peer,
        db,
        puzzle_hashes,
        genesis_challenge,
        peer_ip,
        events,
        trust,
    )
    .await
}

/// The one peer call [`initial_sync`] makes, behind a trait.
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

/// [`initial_sync`] over any [`PuzzleStateSource`]. Production passes a `Peer`.
pub async fn initial_sync_with(
    peer: &dyn PuzzleStateSource,
    db: &WalletDb,
    puzzle_hashes: Vec<Bytes32>,
    genesis_challenge: Bytes32,
    peer_ip: &str,
    events: &EventBus,
    trust: PeerTrust,
) -> Result<(), SyncError> {
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
    if puzzle_hashes.is_empty() {
        return Err(SyncError::NoPuzzleHashes);
    }

    let subscribed: SubscribedHashes = puzzle_hashes.iter().copied().collect();
    let mut previous_height: Option<u32> = None;
    let mut header_hash = genesis_challenge;
    events.publish(SyncEvent::Start {
        ip: peer_ip.to_string(),
    });

    let mut first_batch = true;
    let mut budget = CatchUpBudget::new();
    loop {
        let respond = peer
            .request_puzzle_state(puzzle_hashes.clone(), previous_height, header_hash)
            .await?;
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

        apply_coin_states(db, &respond.coin_states, &subscribed).await?;
        events.publish(SyncEvent::PuzzleBatchSynced);

        if respond.is_finished {
            // ONE statement ends the catch-up: the peak, the authoritative flag, and the arrival
            // baseline are armed together from this response's own values. Splitting them is how
            // the baseline came to be armable by a caller that had replayed nothing
            // (dig_ecosystem#2548) -- see `WalletDb::complete_catch_up`.
            db.complete_catch_up(&CatchUpReplay::finished_at(
                respond.height,
                hex::encode(respond.header_hash),
            ))
            .await?;
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
/// [`initial_sync`]; it returns when the peer disconnects, at which point it publishes
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
                    handle_coin_state_update(db, &update, events, session).await?;
                    if let Some(a) = attributor {
                        a.attribute(db).await?;
                    }
                }
            }
            ProtocolMessageTypes::NewPeakWallet => {
                if let Ok(peak) = decode::<NewPeakWallet>(&message) {
                    // A discovered peer's height is not written, for the same reason its coins
                    // are not: `new_peak_wallet` is the CHEAPEST frame on the wire to lie in,
                    // and the value it would land in is the one a caller divides into a
                    // confirmation count (see [`PeerTrust`]).
                    if !session.trust.is_authoritative() {
                        tracing::debug!(
                            claimed = peak.height,
                            "wallet sync: dropping a new_peak_wallet from a discovered peer"
                        );
                        continue;
                    }
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
                    db.set_peak(peak.height, state.header_hash.as_deref().unwrap_or(""))
                        .await?;
                }
            }
            _ => {}
        }
    }
    events.publish(SyncEvent::Stop);
    Ok(())
}

fn decode<T: chia::traits::Streamable>(message: &Message) -> Result<T, SyncError> {
    T::from_bytes(&message.data).map_err(|e| SyncError::Peer(format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sage::db::WalletDb;

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
        SessionState::new(subscribed, PeerTrust::Operator)
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
            data: chia::traits::Streamable::to_bytes(&peak).unwrap().into(),
        }
    }

    /// A session over a peer this node merely DISCOVERED — writes nothing.
    fn discovered(subscribed: &SubscribedHashes) -> SessionState<'_> {
        SessionState::new(subscribed, PeerTrust::Discovered)
    }

    fn state(c: Coin, created: Option<u32>, spent: Option<u32>) -> CoinState {
        CoinState {
            coin: c,
            created_height: created,
            spent_height: spent,
        }
    }

    #[tokio::test]
    async fn apply_coin_states_persists_and_computes_balance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let states = vec![
            state(coin(1, 9, 1_000), Some(10), None),
            state(coin(2, 9, 2_000), Some(11), None),
        ];
        apply_coin_states(&db, &states, &subscribed_owned())
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 3_000);
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn later_spend_state_marks_coin_spent() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let c = coin(1, 9, 500);
        apply_coin_states(&db, &[state(c, Some(10), None)], &subscribed_owned())
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 500);
        // The peer later reports the same coin as spent.
        apply_coin_states(&db, &[state(c, Some(10), Some(20))], &subscribed_owned())
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
        )
        .await
        .unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(20, "aa"))
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
        db.complete_catch_up(&CatchUpReplay::finished_at(100, "aa"))
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
        )
        .await
        .unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
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
                data: chia::traits::Streamable::to_bytes(&peak).unwrap().into(),
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

    /// **Proves (T1, #2501):** [`initial_sync_with`] REFUSES an empty puzzle-hash set, and
    /// the DB is left un-synced.
    ///
    /// The peer double here would happily report `is_finished` on the first response, so
    /// without the guard the function reaches `set_initial_sync_complete(true)` over a DB
    /// that was never queried for a single coin — and `routing::route(true, true)` then
    /// answers every wallet-scoped read from it. This is the floor of that invariant.
    #[tokio::test]
    async fn initial_sync_refuses_an_empty_puzzle_hash_set() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();

        let err = initial_sync_with(
            &CaughtUpAtOnce,
            &db,
            vec![],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            PeerTrust::Operator,
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

        initial_sync_with(
            &AnswersSubscriptionAndSlipsOneIn,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            PeerTrust::Operator,
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
            data: chia::traits::Streamable::to_bytes(&update).unwrap().into(),
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

        let err = initial_sync_with(
            &AnswersSubscriptionAndSlipsOneIn,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            PeerTrust::Discovered,
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
        let err = initial_sync_with(
            &CaughtUpAtOnce,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            PeerTrust::Discovered,
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
        for (trust, claimed, expected) in [
            (PeerTrust::Discovered, u32::MAX, 6_000_000u32),
            (PeerTrust::Operator, 6_000_010, 6_000_010),
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
                &mut SessionState::new(&subscribed, trust),
            )
            .await
            .unwrap();

            assert_eq!(
                db.sync_state().await.unwrap().peak_height,
                Some(expected),
                "{trust:?} peer claiming height {claimed}"
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

        let err = initial_sync_with(
            &peer,
            &db,
            vec![Bytes32::new([OWNED; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
            PeerTrust::Operator,
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
        use crate::sage::singleton::{LineageSource, ParentSpend};
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
            ) -> crate::sage::Result<Option<ParentSpend>> {
                self.hits.fetch_add(1, Ordering::SeqCst);
                Ok(None)
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
            data: chia::traits::Streamable::to_bytes(&update).unwrap().into(),
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
}
