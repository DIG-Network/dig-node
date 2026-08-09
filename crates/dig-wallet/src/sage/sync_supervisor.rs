//! The background chain-sync supervisor (SPEC §18.6, dig_ecosystem#2501/#2408).
//!
//! [`crate::sage::sync`] is a complete subscription loop that, until now, had **no production
//! call site**: nothing connected a peer, nothing subscribed, and so `sync_state.peak_height`
//! stayed NULL on every install. This module is that missing call site — it owns the peer
//! lifecycle (connect, catch up, consume pushes, reconnect with backoff, shut down) and
//! exposes the small amount of live state the DB alone cannot express.
//!
//! # What the DB cannot say
//!
//! [`crate::sage::db::WalletDb::is_synced`] answers "did a catch-up ever finish", which is not
//! the same question as "is this replica currently following the chain". A wallet that caught
//! up yesterday and has been offline since answers `true` there and is plainly not synced now.
//! The missing fact — is a peer attached RIGHT NOW — lives here, in [`SyncHandle`], and
//! [`SyncHandle::status`] composes the two into [`WalletSyncStatus`].
//!
//! # The invariant this module exists to respect
//!
//! **A catch-up is never run over an empty puzzle-hash set.** The floor of that rule is in
//! [`crate::sage::sync::initial_sync`] itself, which refuses with
//! [`SyncError::NoPuzzleHashes`]; the supervisor additionally does not ask. Both, deliberately:
//! marking an un-queried DB initial-sync-complete flips
//! [`crate::sage::routing::route`] to `Source::Db`, at which point a funded wallet reads as
//! empty. A fresh install has zero puzzle hashes, so this is the DEFAULT path, not an edge.
//!
//! # §908
//!
//! Sync is a chain READ plus a write to the node's own local replica. The puzzle hashes come
//! from custody's persisted PUBLIC keys, which are readable while every wallet is locked. No
//! seed is touched and nothing here can sign.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use chia::bls::PublicKey;
use chia::puzzles::standard::StandardArgs;
use chia_protocol::Bytes32;

use super::custody::WalletCustody;
use super::db::WalletDb;
use super::events::EventBus;
use super::sync::{self, SyncError};

/// The initial reconnect delay.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// The reconnect-delay ceiling. Four DNS introducers serve the whole network; a tight loop
/// across many nodes is the failure mode this bounds.
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long a connection must survive before the ladder resets, so a peer that flaps just
/// under the cap does not reset it on every cycle.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// Per-attempt dial timeout for the production factory.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// The observable state
// ---------------------------------------------------------------------------

/// The wallet's sync phase, as a consumer should render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    /// No peer has ever been attached in this process. Nothing is known yet.
    NotStarted,
    /// A peer is attaching, catching up, or the replica is otherwise not both caught up AND
    /// currently following the chain.
    Syncing,
    /// A catch-up has completed AND a peer is attached right now.
    Synced,
}

/// The composed sync status: the phase, the replica's own peak, and the live peer count.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WalletSyncStatus {
    /// The phase a consumer renders.
    pub phase: SyncPhase,
    /// The REPLICA's own peak height. `None` means unknown — never 0-for-unknown, because a
    /// consumer cannot tell a genuine height 0 from "we have not looked".
    pub peak_height: Option<u32>,
    /// Live subscription peers. `Some(0)` is an OBSERVED zero (a supervisor is running and
    /// holds no peer); `None` is unobservable (no supervisor attached at all).
    pub chia_peer_count: Option<u32>,
}

/// Live counters the supervisor writes and the control layer only reads.
#[derive(Debug, Default, Clone, Copy)]
struct Observed {
    /// Whether a peer has ever been attached in this process.
    ever_connected: bool,
    /// Subscription peers held right now — 0 or 1 (see [`SyncSession`] on why one).
    peers: u32,
}

struct SyncHandleInner {
    observed: RwLock<Observed>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

/// A cheap, cloneable handle onto a running supervisor: the live counters, plus the shutdown
/// signal. Dropping every clone does NOT stop the supervisor; call [`SyncHandle::shutdown`].
#[derive(Clone)]
pub struct SyncHandle {
    inner: Arc<SyncHandleInner>,
}

impl SyncHandle {
    fn new() -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = Self {
            inner: Arc::new(SyncHandleInner {
                observed: RwLock::new(Observed::default()),
                shutdown: tx,
            }),
        };
        (handle, rx)
    }

    /// Compose the live counters with the DB's persisted sync state.
    ///
    /// `Synced` requires BOTH a completed catch-up and a peer attached now: an offline
    /// replica is stale, however complete its last catch-up was, and reporting it synced is
    /// the shape that makes a client trust a day-old balance.
    pub async fn status(&self, db: &WalletDb) -> sqlx::Result<WalletSyncStatus> {
        let observed = self.observed();
        let state = db.sync_state().await?;
        let phase = if !observed.ever_connected {
            SyncPhase::NotStarted
        } else if state.initial_sync_complete && observed.peers >= 1 {
            SyncPhase::Synced
        } else {
            SyncPhase::Syncing
        };
        Ok(WalletSyncStatus {
            phase,
            peak_height: state.peak_height,
            chia_peer_count: Some(observed.peers),
        })
    }

    /// Ask the supervisor to stop after the in-flight step completes. Nothing is aborted, so
    /// a DB write already under way finishes.
    pub fn shutdown(&self) {
        let _ = self.inner.shutdown.send(true);
    }

    fn observed(&self) -> Observed {
        *self.inner.observed.read().expect("observed lock poisoned")
    }

    fn set_connected(&self, peers: u32) {
        let mut o = self.inner.observed.write().expect("observed lock poisoned");
        if peers > 0 {
            o.ever_connected = true;
        }
        o.peers = peers;
    }
}

/// The status to report when NO supervisor is attached: the DB's peak is still honest, but the
/// peer count is unobservable rather than zero.
pub async fn status_without_supervisor(db: &WalletDb) -> sqlx::Result<WalletSyncStatus> {
    let state = db.sync_state().await?;
    Ok(WalletSyncStatus {
        phase: SyncPhase::NotStarted,
        peak_height: state.peak_height,
        chia_peer_count: None,
    })
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// Where the supervisor's subscription set comes from. Re-read on every connect attempt, so a
/// wallet created after boot is picked up without restarting the node.
pub trait PuzzleHashSource: Send + Sync {
    /// The puzzle hashes to subscribe. Empty is a legitimate answer (no wallet yet).
    fn puzzle_hashes(&self) -> Vec<Bytes32>;
}

/// Custody's persisted PUBLIC keys, mapped through the crate's established
/// `StandardArgs::curry_tree_hash` p2 derivation (the same mapping
/// [`crate::sage::spend::WalletSigner`] uses). Readable while every wallet is locked — no seed,
/// no signing capability (§908).
impl PuzzleHashSource for WalletCustody {
    fn puzzle_hashes(&self) -> Vec<Bytes32> {
        let mut hashes: Vec<Bytes32> = self
            .custodied_public_keys()
            .iter()
            .map(puzzle_hash_for)
            .collect();
        // A HashSet iteration order is arbitrary; a stable set makes a subscription (and a
        // test asserting one) reproducible.
        hashes.sort();
        hashes
    }
}

/// The p2 puzzle hash a public key controls.
fn puzzle_hash_for(pk: &PublicKey) -> Bytes32 {
    Bytes32::from(StandardArgs::curry_tree_hash(*pk).to_bytes())
}

/// Opens one peer subscription session.
#[async_trait::async_trait]
pub trait SyncSessionFactory: Send + Sync {
    /// Dial a peer and hand back a session bound to it.
    async fn connect(&self) -> Result<Box<dyn SyncSession>, SyncError>;
}

/// One live peer subscription.
///
/// Exactly one at a time, deliberately: `request_puzzle_state(subscribe = true)` is
/// per-connection state, and N peers would drive N interleaved `rollback_above` calls through
/// [`sync::handle_coin_state_update`] into a single DB that is not written for concurrent
/// writers. Redundancy would buy availability at the price of a reorg race on the
/// money-bearing table.
#[async_trait::async_trait]
pub trait SyncSession: Send + Sync {
    /// The address dialed, for the [`crate::sage::events::SyncEvent::Start`] event.
    fn peer_ip(&self) -> String;

    /// Subscribe `puzzle_hashes` and catch the replica up.
    async fn catch_up(
        &self,
        db: &WalletDb,
        puzzle_hashes: Vec<Bytes32>,
        genesis_challenge: Bytes32,
        events: &EventBus,
    ) -> Result<(), SyncError>;

    /// Consume peer pushes until the peer disconnects. Consumes the session.
    async fn run(self: Box<Self>, db: &WalletDb, events: &EventBus) -> Result<(), SyncError>;
}

/// Waiting and the passage of time, injectable so the backoff ladder is testable without a
/// test that actually sleeps for minutes.
#[async_trait::async_trait]
pub trait TimeSource: Send + Sync {
    /// Sleep for `duration`.
    async fn sleep(&self, duration: Duration);
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The production clock.
pub struct TokioTime;

#[async_trait::async_trait]
impl TimeSource for TokioTime {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

/// An exponential reconnect ladder with jitter: 1s, 2s, 4s … capped at 60s.
struct Backoff {
    current: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: BACKOFF_INITIAL,
        }
    }

    /// The next delay, then double the base for the attempt after it.
    fn next_delay(&mut self) -> Duration {
        let base = self.current;
        self.current = (self.current * 2).min(BACKOFF_MAX);
        jitter(base)
    }

    fn reset(&mut self) {
        self.current = BACKOFF_INITIAL;
    }
}

/// Spread `base` by +/-20%.
///
/// Without this, every node that lost its peer at the same moment (an introducer blip, a
/// network's uplink returning) marches back in lockstep onto four DNS introducers. The
/// randomness comes from the wall clock rather than a new `rand` dependency; it needs to be
/// unpredictable to nobody, only uncorrelated between hosts.
fn jitter(base: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // 0..=40 percent, applied as base * (80 + p) / 100.
    let percent = 80 + u64::from(nanos % 41);
    Duration::from_nanos((base.as_nanos() as u64 / 100).saturating_mul(percent))
}

// ---------------------------------------------------------------------------
// The supervisor
// ---------------------------------------------------------------------------

/// Everything the supervisor loop needs. Assembled by [`spawn_supervisor`].
pub struct Supervisor {
    /// The local replica the session writes into.
    pub db: WalletDb,
    /// The subscription set, re-read per attempt.
    pub puzzle_hashes: Arc<dyn PuzzleHashSource>,
    /// Opens peer sessions.
    pub factory: Arc<dyn SyncSessionFactory>,
    /// The shared bus the sync lifecycle publishes to.
    pub events: Arc<EventBus>,
    /// The chain's genesis challenge — where a fresh catch-up starts.
    pub genesis_challenge: Bytes32,
    /// Waiting + the clock.
    pub time: Arc<dyn TimeSource>,
}

/// Spawn the supervisor on the current runtime.
///
/// Returns its handle and the task's `JoinHandle`, so a caller (and
/// `shutdown_stops_the_supervisor_and_the_task_ends`) can observe the task actually ending
/// rather than assuming it did.
pub fn spawn_supervisor(supervisor: Supervisor) -> (SyncHandle, tokio::task::JoinHandle<()>) {
    let (handle, shutdown) = SyncHandle::new();
    let task_handle = handle.clone();
    let join = tokio::spawn(async move { supervisor.run(task_handle, shutdown).await });
    (handle, join)
}

impl Supervisor {
    /// The lifecycle: connect -> (catch up, if there is anything to catch up) -> consume
    /// pushes -> backoff -> reconnect, until shutdown.
    async fn run(self, handle: SyncHandle, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut backoff = Backoff::new();

        while !*shutdown.borrow() {
            let session = match self.factory.connect().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "wallet sync: no peer; backing off");
                    if !self.wait(&mut backoff, &mut shutdown).await {
                        break;
                    }
                    continue;
                }
            };
            handle.set_connected(1);
            let started = self.time.now();

            // The subscription set is re-read HERE, per connection: a wallet created after
            // boot must be picked up, and the subscription is per-connection state anyway.
            //
            // A reconnect re-runs the catch-up from genesis. It must: a fresh peer has no
            // memory of the previous subscription, and resuming from the stored
            // (height, header_hash) is not safe while `run_update_loop`'s `NewPeakWallet` arm
            // advances the height while carrying the OLD hash forward.
            let puzzle_hashes = self.puzzle_hashes.puzzle_hashes();
            if puzzle_hashes.is_empty() {
                // Nothing to subscribe. The session still runs: `new_peak_wallet` needs no
                // subscription, so the replica's peak keeps advancing, and `is_synced()`
                // stays false — which is the truth, and what keeps wallet-scoped reads on
                // the fallback tier.
                tracing::debug!("wallet sync: no custodied puzzle hashes; peak-only session");
            } else if let Err(e) = session
                .catch_up(
                    &self.db,
                    puzzle_hashes,
                    self.genesis_challenge,
                    &self.events,
                )
                .await
            {
                tracing::warn!(error = %e, "wallet sync: catch-up failed");
                handle.set_connected(0);
                if !self.wait(&mut backoff, &mut shutdown).await {
                    break;
                }
                continue;
            }

            let stop = tokio::select! {
                result = session.run(&self.db, &self.events) => {
                    if let Err(e) = result {
                        tracing::warn!(error = %e, "wallet sync: update loop ended in error");
                    }
                    false
                }
                // Dropping the `run` future drops the receiver, which closes the peer. No
                // abort, so any DB write already in flight completes first.
                _ = shutdown.changed() => true,
            };
            handle.set_connected(0);
            if stop {
                break;
            }

            if self.time.now().duration_since(started) >= HEALTHY_SESSION {
                backoff.reset();
            }
            if !self.wait(&mut backoff, &mut shutdown).await {
                break;
            }
        }
        tracing::debug!("wallet sync: supervisor stopped");
    }

    /// Wait out the next backoff delay. Returns `false` if shutdown arrived meanwhile.
    async fn wait(
        &self,
        backoff: &mut Backoff,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> bool {
        let delay = backoff.next_delay();
        tokio::select! {
            () = self.time.sleep(delay) => !*shutdown.borrow(),
            _ = shutdown.changed() => false,
        }
    }
}

// ---------------------------------------------------------------------------
// The production session
// ---------------------------------------------------------------------------

/// Dials real Chia full nodes: the user's own peers first, then — only if the DB's
/// `discover_peers` setting allows it — `chia-query`'s introducer discovery.
pub struct ChiaPeerSessionFactory {
    db: WalletDb,
    network: chia_query::NetworkType,
}

impl ChiaPeerSessionFactory {
    /// A mainnet factory reading its peer list + discovery setting from `db`.
    ///
    /// The `target_peers` network setting is deliberately NOT consulted: the supervisor holds
    /// exactly one subscription peer by design (see [`SyncSession`]), so that Sage-parity
    /// setting has no supervisor meaning. It is left untouched rather than silently reused
    /// for something it does not mean.
    pub fn mainnet(db: WalletDb) -> Self {
        Self {
            db,
            network: chia_query::NetworkType::Mainnet,
        }
    }
}

#[async_trait::async_trait]
impl SyncSessionFactory for ChiaPeerSessionFactory {
    async fn connect(&self) -> Result<Box<dyn SyncSession>, SyncError> {
        // Generated in memory, never file-backed: a node running as a Windows service has no
        // readable `~/.chia`, and a full node accepts any well-formed client certificate, so
        // a file would be pure liability (dig_ecosystem#2210).
        let tls = chia_query::peer::connect::create_generated_tls()
            .map_err(|e| SyncError::Peer(e.to_string()))?;
        let network_id = self.network.network_id().to_string();

        // The user's own peers come first, in order. That is what the `peers` table is FOR;
        // an operator who pointed the wallet at their own full node must not be quietly
        // routed onto a stranger's.
        let user_peers = self.db.all_peers().await.unwrap_or_default();
        for row in user_peers.iter().filter(|p| p.user_managed) {
            let Ok(ip) = row.ip_addr.parse::<std::net::IpAddr>() else {
                continue;
            };
            let addr = std::net::SocketAddr::new(ip, row.port as u16);
            match tokio::time::timeout(
                DIAL_TIMEOUT,
                chia_wallet_sdk::client::connect_peer(
                    network_id.clone(),
                    tls.clone(),
                    addr,
                    chia_wallet_sdk::client::PeerOptions::default(),
                ),
            )
            .await
            {
                Ok(Ok((peer, receiver))) => {
                    return Ok(Box::new(ChiaPeerSession {
                        peer,
                        ip: addr.to_string(),
                        receiver: tokio::sync::Mutex::new(Some(receiver)),
                    }))
                }
                Ok(Err(e)) => tracing::debug!(%addr, error = %e, "wallet sync: user peer refused"),
                Err(_) => tracing::debug!(%addr, "wallet sync: user peer timed out"),
            }
        }

        // Discovery is opt-out. With it off and no user peer reachable, nothing is
        // fabricated: the supervisor simply stays peerless and retries the user's list.
        let discover = self
            .db
            .network_settings()
            .await
            .map(|s| s.discover_peers)
            .unwrap_or(true);
        if !discover {
            return Err(SyncError::Peer(
                "no user-managed peer reachable and peer discovery is disabled".into(),
            ));
        }

        let (peer, addr, receiver) =
            chia_query::peer::connect::connect_random_peer(self.network, &tls, DIAL_TIMEOUT)
                .await
                .map_err(|e| SyncError::Peer(e.to_string()))?;
        Ok(Box::new(ChiaPeerSession {
            peer,
            ip: addr.to_string(),
            receiver: tokio::sync::Mutex::new(Some(receiver)),
        }))
    }
}

/// One live `chia-wallet-sdk` peer connection.
struct ChiaPeerSession {
    peer: chia_wallet_sdk::client::Peer,
    ip: String,
    /// Taken by [`SyncSession::run`]. Behind a mutex only because the trait's `catch_up` takes
    /// `&self`; exactly one `run` ever consumes it.
    receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<chia::protocol::Message>>>,
}

#[async_trait::async_trait]
impl SyncSession for ChiaPeerSession {
    fn peer_ip(&self) -> String {
        self.ip.clone()
    }

    async fn catch_up(
        &self,
        db: &WalletDb,
        puzzle_hashes: Vec<Bytes32>,
        genesis_challenge: Bytes32,
        events: &EventBus,
    ) -> Result<(), SyncError> {
        sync::initial_sync(
            &self.peer,
            db,
            puzzle_hashes,
            genesis_challenge,
            &self.ip,
            events,
        )
        .await
    }

    async fn run(self: Box<Self>, db: &WalletDb, events: &EventBus) -> Result<(), SyncError> {
        let receiver = self
            .receiver
            .lock()
            .await
            .take()
            .ok_or_else(|| SyncError::Peer("sync session already consumed".into()))?;
        sync::run_update_loop(db, receiver, events, None).await
    }
}

#[cfg(test)]
mod tests;
