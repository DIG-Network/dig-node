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

use super::db::{CoinRow, WalletDb};
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
/// # What a discovered peer may and may not do
///
/// It MAY advance the replica's chain peak, monotonically — that is a public, checkable,
/// non-destructive fact, and it is what powers `control.wallet.syncStatus` and the status
/// display. It MAY NOT write coins, roll the replica back, or set `initial_sync_complete`. That
/// last one is the whole point: [`crate::sage::routing::route`] keys wallet-scoped reads on that
/// flag, so a peer that cannot set it can never make its own answers authoritative for money,
/// no matter how it lies or how many times it reconnects.
///
/// The alternative — patching each individual leak — was tried and walked around: an attacker
/// that empties the replica and then simply closes the socket gets a fresh catch-up on the
/// supervisor's next backoff cycle, and the flag comes back over whatever it chooses to answer.
/// The fix has to be that an untrusted peer never reaches the flag at all.
///
/// The deliberate cost is that a default install (no operator-chosen peer) does not get a full
/// coin sync, and wallet-scoped reads stay on the fallback tier — which is exactly where they
/// were before this module had a production call site. Establishing trust in a discovered peer
/// is a separate decision (dig_ecosystem#2515).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// A `user_managed` row in the `peers` table: an address the operator chose. Full
    /// authority — catch-up, rollback, and the `initial_sync_complete` flag.
    Operator,
    /// Found by DNS introducer or the loopback probe. Advisory only: peak, and nothing else.
    Discovered,
}

impl PeerTrust {
    /// Whether this peer's answers may make the local replica authoritative for money.
    pub fn is_authoritative(self) -> bool {
        matches!(self, PeerTrust::Operator)
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
    /// The puzzle hashes this session subscribed. Empty for a peak-only session.
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
/// # A discovered peer takes the advisory path
///
/// When `session.trust` is [`PeerTrust::Discovered`] this does exactly one thing: advance the
/// peak, monotonically. No rollback, no coin write, no touching the routing flag. Every
/// destructive verb in this function is reachable only through a peer the operator chose.
pub async fn handle_coin_state_update(
    db: &WalletDb,
    update: &CoinStateUpdate,
    events: &EventBus,
    session: &mut SessionState<'_>,
) -> Result<(), SyncError> {
    let current_peak = db.sync_state().await?.peak_height;
    if !session.trust.is_authoritative() {
        return advance_peak_only(db, update, current_peak).await;
    }
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
    events.publish(SyncEvent::CoinState);
    Ok(())
}

/// The advisory half of [`handle_coin_state_update`]: take the peak if it moves FORWARD and
/// discard everything else the frame claims.
///
/// A discovered peer's `coin_state_update` is not evidence about this wallet's money — the
/// wallet handed that peer its own puzzle-hash set, so every hash the peer can name is one it
/// was just given, and the subscription filter proves nothing against it. What the frame does
/// carry is a height, which is public and cheap to be wrong about in only one direction: taking
/// it only when it advances means the worst a hostile peer achieves is a peak that is too high,
/// which makes a confirmation read MORE conservative, never less.
async fn advance_peak_only(
    db: &WalletDb,
    update: &CoinStateUpdate,
    current_peak: Option<u32>,
) -> Result<(), SyncError> {
    if current_peak.is_some_and(|peak| update.height <= peak) {
        tracing::debug!(
            claimed = update.height,
            current = ?current_peak,
            "wallet sync: discarding a non-advancing coin_state_update from a discovered peer"
        );
        return Ok(());
    }
    db.set_peak(update.height, &hex::encode(update.peak_hash))
        .await?;
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
    // THE TRUST BOUNDARY. This function is the ONLY thing in the crate that sets
    // `initial_sync_complete`, and that flag is what `routing::route` turns into "the local
    // replica answers for money". So the check belongs HERE, at the floor, rather than only in
    // the supervisor that decides which peer to dial: a supervisor-side check is one refactor —
    // or one reconnect after a hostile disconnect — away from gone, which is precisely how the
    // previous, per-leak version of this defence was walked around.
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
            db.set_peak(respond.height, &hex::encode(respond.header_hash))
                .await?;
            break;
        }
        // Continue from where this batch ended.
        previous_height = Some(respond.height);
        header_hash = respond.header_hash;
    }

    db.set_initial_sync_complete(true).await?;
    Ok(())
}

/// Consume peer pushes on the receiver until it closes: `coin_state_update` →
/// [`handle_coin_state_update`]; `new_peak_wallet` → advance the peak. This is the
/// production loop run after [`initial_sync`]; it returns when the peer disconnects, at
/// which point it publishes [`SyncEvent::Stop`] on `events`.
///
/// When `attributor` is `Some`, each applied `coin_state_update` is followed by a CAT/
/// singleton attribution pass (#407) so newly-synced CAT coins gain their `asset_id`. When
/// `None`, coins are stored as-is (attribution runs elsewhere / not at all).
///
/// `session` carries the puzzle-hash set this session actually subscribed (pushed coins outside
/// it are dropped — see [`apply_coin_states`]; an empty set is meaningful and correct, because a
/// peak-only session subscribes nothing and must therefore write no coins), how far its peer is
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

    /// A session over a peer this node merely DISCOVERED — advisory only.
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
        .expect("an advisory frame is discarded, not an error");

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

    /// **Proves (F1c):** the one thing a discovered peer MAY do - advance the peak - still
    /// works, and only forwards.
    ///
    /// Without this the trust boundary could be satisfied by ignoring discovered peers entirely,
    /// which would take the live sync status down with it. The backwards frame in the same test
    /// is the control that stops "just take whatever height it says" from passing.
    #[tokio::test]
    async fn a_discovered_peer_advances_the_peak_but_never_retreats_it() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(6_000_000, "aa").await.unwrap();
        let events = EventBus::default();
        let subscribed = subscribed_owned();

        for (height, expected) in [(6_000_010u32, 6_000_010u32), (5_000_000, 6_000_010)] {
            handle_coin_state_update(
                &db,
                &CoinStateUpdate {
                    height,
                    fork_height: height.saturating_sub(1),
                    peak_hash: Bytes32::new([7; 32]),
                    // A coin at the SUBSCRIBED hash, which an authoritative session would
                    // write: it must not land here either.
                    items: vec![state(coin(1, OWNED, 999), Some(height), None)],
                },
                &events,
                &mut discovered(&subscribed),
            )
            .await
            .unwrap();
            assert_eq!(
                db.sync_state().await.unwrap().peak_height,
                Some(expected),
                "the peak advances forward only"
            );
        }
        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "an advisory frame writes no coins, even at a subscribed hash"
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
