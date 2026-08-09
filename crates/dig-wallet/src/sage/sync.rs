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
}

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

/// Apply a batch of `CoinState`s into the DB (the core of `coin_state_update`). Each state
/// is upserted by coin id, so a later spend overwrites the earlier unspent row.
pub async fn apply_coin_states(db: &WalletDb, states: &[CoinState]) -> Result<(), SyncError> {
    let rows: Vec<CoinRow> = states.iter().map(coin_state_to_row).collect();
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
pub async fn handle_coin_state_update(
    db: &WalletDb,
    update: &CoinStateUpdate,
    events: &EventBus,
) -> Result<(), SyncError> {
    let current_peak = db.sync_state().await?.peak_height;
    if let Some(peak) = current_peak {
        if update.fork_height < peak {
            db.rollback_above(update.fork_height).await?;
        }
    }
    apply_coin_states(db, &update.items).await?;
    db.set_peak(update.height, &hex::encode(update.peak_hash))
        .await?;
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
) -> Result<(), SyncError> {
    initial_sync_with(peer, db, puzzle_hashes, genesis_challenge, peer_ip, events).await
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
) -> Result<(), SyncError> {
    // THE INVARIANT. An empty subscription is answered `is_finished` at once, and the
    // completion flag below would then declare an un-queried DB authoritative for every
    // wallet-scoped read (`routing::route(true, true) == Source::Db`). The guard lives HERE,
    // at the floor, and not only in the supervisor that calls it: a caller-side check is one
    // refactor away from gone, and this function is the only thing that can set the flag.
    if puzzle_hashes.is_empty() {
        return Err(SyncError::NoPuzzleHashes);
    }

    let mut previous_height: Option<u32> = None;
    let mut header_hash = genesis_challenge;
    events.publish(SyncEvent::Start {
        ip: peer_ip.to_string(),
    });

    let mut first_batch = true;
    loop {
        let respond = peer
            .request_puzzle_state(puzzle_hashes.clone(), previous_height, header_hash)
            .await?;
        if first_batch {
            events.publish(SyncEvent::Subscribed);
            first_batch = false;
        }

        apply_coin_states(db, &respond.coin_states).await?;
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
pub async fn run_update_loop(
    db: &WalletDb,
    mut receiver: tokio::sync::mpsc::Receiver<Message>,
    events: &EventBus,
    attributor: Option<&CatAttributor<'_>>,
) -> Result<(), SyncError> {
    while let Some(message) = receiver.recv().await {
        match message.msg_type {
            ProtocolMessageTypes::CoinStateUpdate => {
                if let Ok(update) = decode::<CoinStateUpdate>(&message) {
                    handle_coin_state_update(db, &update, events).await?;
                    if let Some(a) = attributor {
                        a.attribute(db).await?;
                    }
                }
            }
            ProtocolMessageTypes::NewPeakWallet => {
                if let Ok(peak) = decode::<NewPeakWallet>(&message) {
                    let hh = db.sync_state().await?.header_hash;
                    // Only advance the recorded peak height (no rollback on a forward peak).
                    db.set_peak(peak.height, hh.as_deref().unwrap_or(""))
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
        apply_coin_states(&db, &states).await.unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 3_000);
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn later_spend_state_marks_coin_spent() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let c = coin(1, 9, 500);
        apply_coin_states(&db, &[state(c, Some(10), None)])
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 500);
        // The peer later reports the same coin as spent.
        apply_coin_states(&db, &[state(c, Some(10), Some(20))])
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn coin_state_update_reorg_rolls_back_then_applies() {
        let db = WalletDb::open_in_memory().await.unwrap();
        // Build initial state at peak 40.
        apply_coin_states(&db, &[state(coin(1, 9, 5), Some(10), Some(30))])
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
        handle_coin_state_update(&db, &update, &events)
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
        apply_coin_states(&db, &[state(coin(1, 9, 5), Some(10), None)])
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
        handle_coin_state_update(&db, &update, &events)
            .await
            .unwrap();
        assert_eq!(db.balance(None).await.unwrap(), 8);
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(50));
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

    /// **Proves:** the same catch-up path DOES complete — and sets the flag — once there is
    /// at least one puzzle hash. Without this control, T1 would also pass if `initial_sync`
    /// simply never worked.
    #[tokio::test]
    async fn initial_sync_completes_over_a_non_empty_puzzle_hash_set() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let events = EventBus::default();

        initial_sync_with(
            &CaughtUpAtOnce,
            &db,
            vec![Bytes32::new([4; 32])],
            Bytes32::new([0; 32]),
            "127.0.0.1",
            &events,
        )
        .await
        .expect("a non-empty subscription set catches up normally");

        assert!(db.is_synced().await.unwrap());
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(6_000_000));
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

        run_update_loop(&db, receiver, &events, None).await.unwrap();

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

        run_update_loop(&db, receiver, &events, None).await.unwrap();

        assert_eq!(rx.recv().await.unwrap(), SyncEvent::CoinState);
        assert_eq!(rx.recv().await.unwrap(), SyncEvent::Stop);
        assert_eq!(db.balance(None).await.unwrap(), 42);
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
        run_update_loop(&db, receiver, &events, Some(&attributor))
            .await
            .unwrap();

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "attributor fetched the candidate coin's parent spend"
        );
    }
}
