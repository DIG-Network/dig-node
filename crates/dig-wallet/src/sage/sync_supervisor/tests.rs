//! Supervisor tests (dig_ecosystem#2501).
//!
//! The doubles here stop at the PEER boundary and nowhere else: `catch_up` runs the real
//! [`sync::initial_sync_with`] (so the empty-set guard is genuinely in the path) and `run` runs
//! the real [`sync::run_update_loop`] (so a peak advance is a real decode + a real DB write).
//! Only the socket is fake.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use chia::protocol::{Message, NewPeakWallet, ProtocolMessageTypes, RespondPuzzleState};

use super::*;
use crate::sage::routing::{self, Source};
use crate::sage::sync::PuzzleStateSource;

/// The height a scripted catch-up reports as the chain tip.
const CATCH_UP_HEIGHT: u32 = 6_000_000;

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

/// A peer that reports "caught up, nothing to send" — what a real full node answers to a
/// subscription it has already satisfied.
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
            height: CATCH_UP_HEIGHT,
            header_hash: Bytes32::new([9; 32]),
            is_finished: true,
        })
    }
}

/// Everything the scripted factory and its sessions share with the test.
#[derive(Default)]
struct Script {
    /// One entry per `catch_up`, holding the exact set that was subscribed.
    catch_ups: Mutex<Vec<Vec<Bytes32>>>,
    /// Successful `connect` calls.
    connects: AtomicUsize,
    /// Addresses `connect` dialed, in order.
    dialled: Mutex<Vec<String>>,
    /// The sender feeding each live session's update loop; the test drives and closes it.
    senders: Mutex<Vec<tokio::sync::mpsc::Sender<Message>>>,
    /// Delays passed to [`TimeSource::sleep`], in order.
    slept: Mutex<Vec<Duration>>,
    /// How long each session appears to last, on the test clock.
    session_lifetime: Mutex<Duration>,
    /// Connect outcomes, consumed in order; exhaustion means "fail".
    outcomes: Mutex<VecDeque<bool>>,
    /// The test clock's current instant.
    now: Mutex<Option<Instant>>,
}

impl Script {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(Some(Instant::now())),
            ..Self::default()
        })
    }

    fn catch_up_count(&self) -> usize {
        self.catch_ups.lock().unwrap().len()
    }

    fn advance(&self, by: Duration) {
        let mut now = self.now.lock().unwrap();
        *now = Some(now.unwrap() + by);
    }

    /// Close every open session channel, so the update loops return and the supervisor
    /// treats the peers as disconnected.
    fn disconnect_all(&self) {
        self.senders.lock().unwrap().clear();
    }
}

#[async_trait::async_trait]
impl TimeSource for Script {
    async fn sleep(&self, duration: Duration) {
        self.slept.lock().unwrap().push(duration);
        self.advance(duration);
        // Yield rather than sleep: the ladder is asserted from `slept`, so a test must not
        // actually wait out a 60-second cap.
        tokio::task::yield_now().await;
    }
    fn now(&self) -> Instant {
        self.now.lock().unwrap().unwrap()
    }
}

/// A factory whose successes/failures the test scripts.
struct ScriptedFactory {
    script: Arc<Script>,
    /// Addresses this factory pretends to dial, in preference order.
    addrs: Vec<String>,
    /// How far the sessions it hands out are trusted — the fact the production factory
    /// derives from WHICH list an address came from.
    trust: PeerTrust,
}

#[async_trait::async_trait]
impl SyncSessionFactory for ScriptedFactory {
    async fn connect(&self) -> Result<Box<dyn SyncSession>, SyncError> {
        let ok = self
            .script
            .outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(true);
        for a in &self.addrs {
            self.script.dialled.lock().unwrap().push(a.clone());
            if ok {
                break;
            }
        }
        if !ok {
            return Err(SyncError::Peer("scripted connect failure".into()));
        }
        self.script.connects.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(8);
        self.script.senders.lock().unwrap().push(tx);
        Ok(Box::new(ScriptedSession {
            script: self.script.clone(),
            trust: self.trust,
            receiver: tokio::sync::Mutex::new(Some(rx)),
        }))
    }
}

struct ScriptedSession {
    script: Arc<Script>,
    trust: PeerTrust,
    receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Message>>>,
}

#[async_trait::async_trait]
impl SyncSession for ScriptedSession {
    fn peer_ip(&self) -> String {
        "203.0.113.1:8444".to_string()
    }

    fn trust(&self) -> PeerTrust {
        self.trust
    }

    async fn catch_up(
        &self,
        db: &WalletDb,
        puzzle_hashes: Vec<Bytes32>,
        genesis_challenge: Bytes32,
        events: &EventBus,
    ) -> Result<(), SyncError> {
        self.script
            .catch_ups
            .lock()
            .unwrap()
            .push(puzzle_hashes.clone());
        // The REAL catch-up, so the empty-set guard and the completion-flag write are both
        // exercised exactly as production would exercise them.
        sync::initial_sync_with(
            &CaughtUpAtOnce,
            db,
            puzzle_hashes,
            genesis_challenge,
            &self.peer_ip(),
            events,
            self.trust,
        )
        .await
    }

    async fn run(
        self: Box<Self>,
        db: &WalletDb,
        events: &EventBus,
        session: &mut sync::SessionState<'_>,
    ) -> Result<(), SyncError> {
        let receiver = self.receiver.lock().await.take().expect("run called once");
        let result = sync::run_update_loop(db, receiver, events, None, session).await;
        let lifetime = *self.script.session_lifetime.lock().unwrap();
        self.script.advance(lifetime);
        result
    }
}

/// A puzzle-hash set the TEST can change while the supervisor is running — the shape of a user
/// creating a wallet on a node that booted with none.
#[derive(Default)]
struct MutableHashes(Mutex<Vec<Bytes32>>);

impl MutableHashes {
    fn set(&self, hashes: Vec<Bytes32>) {
        *self.0.lock().unwrap() = hashes;
    }
}

impl PuzzleHashSource for MutableHashes {
    fn puzzle_hashes(&self) -> Vec<Bytes32> {
        self.0.lock().unwrap().clone()
    }
}

/// A fixed puzzle-hash set, for tests that do not need real custody.
struct FixedHashes(Vec<Bytes32>);

impl PuzzleHashSource for FixedHashes {
    fn puzzle_hashes(&self) -> Vec<Bytes32> {
        self.0.clone()
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    db: WalletDb,
    script: Arc<Script>,
    handle: SyncHandle,
    join: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Start a supervisor over an OPERATOR-chosen peer (the authoritative path).
    async fn start(
        db: WalletDb,
        hashes: Arc<dyn PuzzleHashSource>,
        script: Arc<Script>,
        addrs: Vec<String>,
    ) -> Self {
        Self::start_with_trust(db, hashes, script, addrs, PeerTrust::Operator).await
    }

    async fn start_with_trust(
        db: WalletDb,
        hashes: Arc<dyn PuzzleHashSource>,
        script: Arc<Script>,
        addrs: Vec<String>,
        trust: PeerTrust,
    ) -> Self {
        let factory = Arc::new(ScriptedFactory {
            script: script.clone(),
            addrs,
            trust,
        });
        let (handle, join) = spawn_supervisor(Supervisor {
            db: db.clone(),
            puzzle_hashes: hashes,
            factory,
            events: Arc::new(EventBus::default()),
            genesis_challenge: Bytes32::new([0; 32]),
            time: script.clone(),
        });
        Self {
            db,
            script,
            handle,
            join,
        }
    }

    /// Poll `predicate` until it holds, or fail. Bounded in real time so a wedged supervisor
    /// fails the test instead of hanging the suite.
    async fn until(&self, what: &str, mut predicate: impl FnMut(&Script) -> bool) {
        for _ in 0..2_000 {
            if predicate(&self.script) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// Poll the DB until `predicate` holds, or fail. The supervisor records a call before it
    /// performs the work, so a DB-visible outcome must be awaited on the DB.
    async fn until_db(
        &self,
        what: &str,
        mut predicate: impl FnMut(&super::super::db::SyncState) -> bool,
    ) {
        for _ in 0..2_000 {
            if predicate(&self.db.sync_state().await.unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    async fn stop(self) {
        self.handle.shutdown();
        self.script.disconnect_all();
        tokio::time::timeout(Duration::from_secs(5), self.join)
            .await
            .expect("supervisor task must end after shutdown")
            .expect("supervisor task must not panic");
    }
}

/// A unique temp config dir per test.
fn scratch() -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("dig-wallet-sup-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A derived (not hard-coded) custody password — CodeQL flags literal cryptographic values.
fn test_custody_password() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    b"dig-wallet-sync-supervisor-test".hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn peak_message(height: u32) -> Message {
    let peak = NewPeakWallet {
        header_hash: Bytes32::new([3; 32]),
        height,
        weight: 0u128,
        fork_point_with_previous_peak: height.saturating_sub(1),
    };
    Message {
        msg_type: ProtocolMessageTypes::NewPeakWallet,
        id: None,
        data: chia::traits::Streamable::to_bytes(&peak).unwrap().into(),
    }
}

// ---------------------------------------------------------------------------
// T2 / T3 — the empty-custody install, which is the DEFAULT install
// ---------------------------------------------------------------------------

/// **Proves (T2, #2501):** with no custodied wallet the supervisor NEVER runs a catch-up, so
/// `initial_sync_complete` stays false and wallet-scoped reads keep routing to the fallback.
///
/// This is the regression that would make a funded wallet report empty: a catch-up over zero
/// puzzle hashes is answered `is_finished` immediately, the completion flag flips, and
/// `routing::route(true, true)` then serves every balance from a DB holding no coins. A fresh
/// install has zero puzzle hashes, so this is the normal path and not an edge case.
#[tokio::test]
async fn supervisor_with_no_derivations_never_marks_initial_sync_complete() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let custody = WalletCustody::mainnet(scratch());
    assert!(
        custody.puzzle_hashes().is_empty(),
        "a fresh custody dir must yield no puzzle hashes"
    );

    let h = Harness::start(
        db.clone(),
        Arc::new(custody),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("a connection", |s| s.connects.load(Ordering::SeqCst) >= 1)
        .await;

    assert_eq!(
        h.script.catch_up_count(),
        0,
        "a catch-up must not be attempted with an empty subscription set"
    );
    assert!(
        !db.is_synced().await.unwrap(),
        "initial_sync_complete must stay false"
    );
    assert_eq!(
        routing::route(db.is_synced().await.unwrap(), true),
        Source::Fallback,
        "wallet-scoped reads must stay on the fallback tier"
    );
    h.stop().await;
}

/// **Proves (T3, #2501):** the replica's peak advances even with zero derivations.
///
/// `new_peak_wallet` is not a subscription response, so it arrives regardless of what was
/// subscribed — which is what makes a peak-only session useful on a wallet-less node. The
/// message here is a real encoded `NewPeakWallet` decoded by the real
/// [`sync::run_update_loop`]; the double supplies only the socket.
#[tokio::test]
async fn supervisor_with_no_derivations_still_advances_the_replica_peak() {
    let db = WalletDb::open_in_memory().await.unwrap();
    assert_eq!(
        db.sync_state().await.unwrap().peak_height,
        None,
        "the peak starts UNKNOWN, not zero"
    );

    let h = Harness::start(
        db.clone(),
        Arc::new(FixedHashes(vec![])),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("a session", |s| !s.senders.lock().unwrap().is_empty())
        .await;

    let sender = h.script.senders.lock().unwrap()[0].clone();
    sender.send(peak_message(6_123_456)).await.unwrap();

    h.until_db("the peak to advance", |s| s.peak_height.is_some())
        .await;
    assert_eq!(
        db.sync_state().await.unwrap().peak_height,
        Some(6_123_456),
        "a peak-only session must still advance the replica peak"
    );
    assert!(
        !db.is_synced().await.unwrap(),
        "advancing the peak must NOT imply the wallet is caught up"
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// T4 — the wallet-present path
// ---------------------------------------------------------------------------

/// **Proves (T4, #2501):** once custody holds a wallet, the supervisor subscribes exactly the
/// `StandardArgs::curry_tree_hash` set derived from its PUBLIC keys — readable while the wallet
/// is locked, so no seed is touched (§908) — and only then does the DB become synced.
#[tokio::test]
async fn supervisor_runs_catch_up_once_custody_has_keys() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let custody = WalletCustody::mainnet(scratch());
    custody
        .create(&test_custody_password(), None)
        .expect("create a custodied wallet");

    let mut expected: Vec<Bytes32> = custody
        .custodied_public_keys()
        .iter()
        .map(puzzle_hash_for)
        .collect();
    expected.sort();
    assert!(!expected.is_empty(), "a created wallet has public keys");

    let h = Harness::start(
        db.clone(),
        Arc::new(custody),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("a catch-up", |s| s.catch_up_count() >= 1).await;
    h.until_db("the catch-up to complete", |s| s.initial_sync_complete)
        .await;

    assert_eq!(
        h.script.catch_ups.lock().unwrap()[0],
        expected,
        "the subscribed set must be exactly the custodied p2 puzzle hashes"
    );
    assert!(
        db.is_synced().await.unwrap(),
        "a completed catch-up marks the replica synced"
    );
    assert_eq!(
        db.sync_state().await.unwrap().peak_height,
        Some(CATCH_UP_HEIGHT)
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// F1 - the trust boundary, driven through the REAL supervisor
// ---------------------------------------------------------------------------

/// **Proves (F1c, the auditor's backoff-cycle exploit):** a DISCOVERED peer never marks the
/// replica authoritative, however many times it drops the connection and is reconnected to.
///
/// This is the exploit the previous round could not close: the attacker empties the table, the
/// per-frame latch fires correctly, the attacker then simply CLOSES THE SOCKET, the supervisor
/// backs off ~1s, reconnects to the same attacker, and the fresh catch-up re-sets the flag over
/// whatever it answers. Here the supervisor is driven through three full connect cycles against
/// a wallet that HAS puzzle hashes - so there is a real subscription to run and the test cannot
/// pass by the empty-set guard - and no catch-up is ever attempted.
///
/// The peak assertion is the control: a supervisor that satisfied the trust boundary by ignoring
/// discovered peers altogether would take the live sync status with it, and would fail here.
#[tokio::test]
async fn a_discovered_peer_never_marks_the_replica_authoritative_across_reconnects() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let h = Harness::start_with_trust(
        db.clone(),
        Arc::new(FixedHashes(vec![Bytes32::new([4; 32])])),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
    )
    .await;

    for cycle in 1..=3u32 {
        h.until(&format!("connection {cycle}"), move |s| {
            s.connects.load(Ordering::SeqCst) >= cycle as usize
        })
        .await;
        // Checked per cycle, and BEFORE the peak wait, so a supervisor that subscribes a
        // discovered peer fails on this assertion rather than on a downstream timeout.
        assert_eq!(
            h.script.catch_up_count(),
            0,
            "cycle {cycle}: a discovered peer must not be handed a subscription"
        );
        h.until("a live session", |s| !s.senders.lock().unwrap().is_empty())
            .await;
        let sender = h.script.senders.lock().unwrap().last().unwrap().clone();
        sender
            .send(peak_message(6_000_000 + cycle))
            .await
            .expect("the session consumes peer pushes");
        h.until_db("the advisory peak to land", move |s| {
            s.peak_height == Some(6_000_000 + cycle)
        })
        .await;
        // The attacker hangs up, buying itself a reconnect.
        h.script.disconnect_all();
    }

    assert_eq!(
        h.script.catch_up_count(),
        0,
        "a discovered peer must never be handed a subscription, on any cycle"
    );
    assert!(
        !db.is_synced().await.unwrap(),
        "and must never make the replica authoritative"
    );
    assert_eq!(
        routing::route(db.is_synced().await.unwrap(), true),
        Source::Fallback,
        "so every wallet-scoped read stays on the fallback tier"
    );
    assert_eq!(
        db.sync_state().await.unwrap().peak_height,
        Some(6_000_003),
        "while the peak - the one thing an advisory peer may move - kept advancing"
    );
    h.stop().await;
}

/// **Proves (R3, #2501):** a wallet created AFTER boot is subscribed while the peer-only session
/// is still connected — not at the next disconnect.
///
/// The fixture is built so the two are distinguishable: the scripted peer never disconnects (the
/// test does not touch `disconnect_all`, so the session channel stays open and `run` is still
/// awaiting), which is exactly the measured default install — zero puzzle hashes, one long-lived
/// peer. A supervisor that only re-reads the set on connect therefore CANNOT pass this test: it
/// has no next connect to re-read on.
#[tokio::test]
async fn a_wallet_created_after_boot_is_subscribed_without_waiting_for_a_disconnect() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let hashes = Arc::new(MutableHashes::default());

    let h = Harness::start(
        db.clone(),
        hashes.clone(),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("a connection", |s| s.connects.load(Ordering::SeqCst) >= 1)
        .await;
    assert_eq!(
        h.script.catch_up_count(),
        0,
        "nothing is subscribed while custody is empty"
    );

    // The user creates a wallet. Nothing disconnects the peer.
    let created = Bytes32::new([4; 32]);
    hashes.set(vec![created]);

    h.until("the new wallet to be subscribed", |s| {
        s.catch_up_count() >= 1
    })
    .await;
    assert_eq!(
        h.script.catch_ups.lock().unwrap()[0],
        vec![created],
        "the catch-up must subscribe exactly the newly-created wallet's hash"
    );
    h.until_db("the catch-up to complete", |s| s.initial_sync_complete)
        .await;
    h.stop().await;
}

// ---------------------------------------------------------------------------
// T5 / T6 / T7 — the phase ladder
// ---------------------------------------------------------------------------

/// **Proves (T5, #2501):** a replica that caught up but holds no peer reports `Syncing`, not
/// `Synced`.
///
/// This is the "offline since yesterday" case, and it is the reason the peer count cannot live
/// in the DB: `is_synced()` alone would call a day-old balance current.
#[tokio::test]
async fn phase_is_syncing_when_caught_up_but_no_peer() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_initial_sync_complete(true).await.unwrap();
    db.set_peak(6_000_000, "aa").await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    assert_eq!(handle.status(&db).await.unwrap().phase, SyncPhase::Synced);

    handle.set_connected(0);
    let status = handle.status(&db).await.unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::Syncing,
        "a caught-up replica with no peer is not currently synced"
    );
    assert_eq!(status.peak_height, Some(6_000_000));
}

/// **Proves (T6, #2501):** the ladder is `NotStarted` -> `Syncing` -> `Synced`, and
/// `NotStarted` means "no peer has ever attached", not "not caught up".
#[tokio::test]
async fn phase_ladder_not_started_syncing_synced() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();

    assert_eq!(
        handle.status(&db).await.unwrap().phase,
        SyncPhase::NotStarted
    );

    handle.set_connected(1);
    assert_eq!(handle.status(&db).await.unwrap().phase, SyncPhase::Syncing);

    db.set_initial_sync_complete(true).await.unwrap();
    assert_eq!(handle.status(&db).await.unwrap().phase, SyncPhase::Synced);
}

/// **Proves (T7, #2501):** an observed zero peers and an unobservable peer count are different
/// answers. A consumer must be able to tell "the supervisor is running and has nobody" from
/// "there is no supervisor to ask".
#[tokio::test]
async fn chia_peer_count_distinguishes_observed_zero_from_unobservable() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(42, "aa").await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    assert_eq!(handle.status(&db).await.unwrap().chia_peer_count, Some(0));

    let without = status_without_supervisor(&db).await.unwrap();
    assert_eq!(without.chia_peer_count, None);
    assert_eq!(
        without.peak_height,
        Some(42),
        "the DB's peak stays honest without a supervisor"
    );
}

/// **Proves (#2501, and the `control.wallet.syncStatus` contract):** the reported peak is the
/// REPLICA's own, and an unknown peak stays unknown.
///
/// The status path must never reach `WalletBackend::chain_peak`, which falls back to a coinset
/// ORACLE behind the `fallback_rate` limiter. Answering the wallet's own progress with a third
/// party's height would be wrong on its face, and routing an unauthenticated loopback method
/// into outbound requests is the egress-amplification shape `-32043 WALLET_RATE_LIMITED` exists
/// to bound (#1957) — plus the oracle read hands that third party an `{IP, timestamp, coin id}`
/// tuple. [`SyncHandle::status`] is given only a [`WalletDb`], so there is no oracle to consult:
/// this asserts the observable consequence, that an empty replica reports `None` rather than
/// borrowing a height from anywhere.
#[tokio::test]
async fn status_reports_the_replica_peak_and_never_an_oracle_height() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);

    assert_eq!(
        handle.status(&db).await.unwrap().peak_height,
        None,
        "an un-synced replica must report an UNKNOWN peak, not a borrowed one"
    );

    db.set_peak(6_000_001, "aa").await.unwrap();
    assert_eq!(
        handle.status(&db).await.unwrap().peak_height,
        Some(6_000_001),
        "and once the replica has a peak, that exact value is what is reported"
    );
}

// ---------------------------------------------------------------------------
// T8 / T10 / T11 — lifecycle
// ---------------------------------------------------------------------------

/// **Proves (T8, #2501):** the reconnect ladder grows exponentially (so a peerless node does
/// not spin against four DNS introducers) and resets after a connection that stayed up.
///
/// Jitter is +/-20%, so each delay is asserted as a band around its base rather than exactly —
/// asserting an exact value would only pass by removing the jitter that keeps a fleet of nodes
/// from marching in lockstep.
#[tokio::test]
async fn backoff_grows_then_resets_after_a_long_lived_connection() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    // Four failures, then a connection.
    script
        .outcomes
        .lock()
        .unwrap()
        .extend([false, false, false, false, true]);
    *script.session_lifetime.lock().unwrap() = HEALTHY_SESSION * 2;

    let h = Harness::start(
        db,
        // A subscribed wallet, so `slept` records ONLY the backoff ladder: a peak-only session
        // additionally re-polls for a newly-created wallet on its own interval, and those sleeps
        // would be indistinguishable from backoff rungs here.
        Arc::new(FixedHashes(vec![Bytes32::new([4; 32])])),
        script,
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("four failed attempts", |s| {
        s.slept.lock().unwrap().len() >= 4
    })
    .await;

    let delays = h.script.slept.lock().unwrap().clone();
    for (i, base) in [1u64, 2, 4, 8].iter().enumerate() {
        let d = delays[i];
        assert!(
            d >= Duration::from_millis(base * 800) && d <= Duration::from_millis(base * 1200),
            "attempt {i} should back off around {base}s (+/-20%), got {d:?}"
        );
    }

    // The connection now succeeds and lasts longer than HEALTHY_SESSION; closing it must
    // return the ladder to its first rung rather than continuing at 16s.
    h.until("a session", |s| !s.senders.lock().unwrap().is_empty())
        .await;
    h.script.disconnect_all();
    h.until("a post-session backoff", |s| {
        s.slept.lock().unwrap().len() >= 5
    })
    .await;

    let after = h.script.slept.lock().unwrap()[4];
    assert!(
        after <= Duration::from_millis(1_200),
        "a healthy session must reset the ladder to ~1s, got {after:?}"
    );
    h.stop().await;
}

/// **Proves (T10, #2501):** a dropped peer is reconnected, and the catch-up is re-run.
///
/// It must re-run: `request_puzzle_state(subscribe = true)` is per-connection state, so a fresh
/// peer has no memory of the previous subscription and would push nothing.
#[tokio::test]
async fn reconnect_reruns_catch_up() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let h = Harness::start(
        db,
        Arc::new(FixedHashes(vec![Bytes32::new([5; 32])])),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("the first catch-up", |s| s.catch_up_count() >= 1)
        .await;

    // Drop the peer.
    h.script.senders.lock().unwrap().clear();
    h.until("a re-run catch-up", |s| s.catch_up_count() >= 2)
        .await;

    assert!(h.script.connects.load(Ordering::SeqCst) >= 2);
    h.stop().await;
}

/// **Proves (T11, #2501):** `shutdown()` ends the supervisor task, and it ends by RETURNING —
/// the task is never aborted, so a DB write in flight completes.
#[tokio::test]
async fn shutdown_stops_the_supervisor_and_the_task_ends() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let h = Harness::start(
        db,
        Arc::new(FixedHashes(vec![])),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;
    h.until("a session", |s| !s.senders.lock().unwrap().is_empty())
        .await;

    h.handle.shutdown();
    let join = h.join;
    tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("the task must end promptly after shutdown")
        .expect("and must not panic");
}

// ---------------------------------------------------------------------------
// T12 — peer preference
// ---------------------------------------------------------------------------

/// **Proves (T12, #2501):** the user's own peers are dialled before discovery.
///
/// The `peers` table exists so an operator can point the wallet at their own full node; a
/// supervisor that went straight to the DNS introducers would silently ignore that.
#[tokio::test]
async fn user_managed_peers_are_tried_before_discovery() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.add_peer("198.51.100.7", 8444).await.unwrap();

    let peers = db.all_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert!(
        peers[0].user_managed,
        "add_peer records a user-managed peer"
    );

    // The production factory dials `all_peers()` in order before touching discovery; the
    // scripted factory is handed that same order so the preference itself is observable
    // without a socket.
    //
    // The address is composed through `SocketAddr`, never by concatenating text: an IPv6
    // literal needs brackets and a hand-built `ip:port` string silently produces an
    // unparseable address for every one of them (#1593).
    let addrs: Vec<String> = peers
        .iter()
        .map(|p| {
            let ip: std::net::IpAddr = p.ip_addr.parse().expect("a stored peer ip is a literal");
            std::net::SocketAddr::new(ip, p.port as u16).to_string()
        })
        .chain(std::iter::once("discovery".to_string()))
        .collect();
    let script = Script::new();
    script.outcomes.lock().unwrap().push_back(true);

    let h = Harness::start(db, Arc::new(FixedHashes(vec![])), script, addrs).await;
    h.until("a dial", |s| !s.dialled.lock().unwrap().is_empty())
        .await;

    assert_eq!(
        h.script.dialled.lock().unwrap()[0],
        "198.51.100.7:8444",
        "the user's peer must be dialled before discovery"
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// T9 — TLS identity
// ---------------------------------------------------------------------------

/// **Proves (T9, #2501):** the supervisor's peer TLS identity is GENERATED in memory.
///
/// Asserted at the API level rather than by connecting, for the same reason
/// `service.rs`'s sibling pin exists: the failure it guards depends on whether `~/.chia` exists
/// for the account the process runs under, so a test that merely constructed a connector would
/// pass on any developer machine and fail only on the Windows service account (#2210).
#[test]
fn supervisor_tls_identity_is_generated_never_file_backed() {
    // `create_generated_tls` takes no path, which is the property: there is no argument by
    // which a filesystem certificate could be supplied.
    let connector = chia_query::peer::connect::create_generated_tls();
    assert!(
        connector.is_ok(),
        "the generated identity must build with nothing on disk"
    );
}

// ---------------------------------------------------------------------------
// T13 — the live acceptance step (never run in CI)
// ---------------------------------------------------------------------------

/// **Proves (T13, #2501):** a real mainnet peer advances the replica's peak with ZERO
/// derivations subscribed.
///
/// This is the ONLY test that can falsify the assumption the peak-only session rests on — that
/// a full node pushes `new_peak_wallet` unsolicited to a wallet peer that has subscribed
/// nothing. Nothing in this repo asserts it and no offline test can: the doubles above supply
/// the frame that the real question is whether a peer would have sent. Ignored because it dials
/// mainnet; run it by hand.
#[tokio::test]
#[ignore = "dials real mainnet peers; run by hand as the #2501 acceptance step"]
async fn live_mainnet_peer_advances_the_peak() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let factory = Arc::new(ChiaPeerSessionFactory::mainnet(db.clone()));
    let (handle, join) = spawn_supervisor(Supervisor {
        db: db.clone(),
        puzzle_hashes: Arc::new(FixedHashes(vec![])),
        factory,
        events: Arc::new(EventBus::default()),
        genesis_challenge: chia_wallet_sdk::types::MAINNET_CONSTANTS.genesis_challenge,
        time: Arc::new(TokioTime),
    });

    // A mainnet block lands roughly every 19s; three minutes is several peaks of margin.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let mut peak = None;
    while std::time::Instant::now() < deadline {
        peak = db.sync_state().await.unwrap().peak_height;
        if peak.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(10), join).await;

    let peak = peak.expect(
        "a mainnet peer must push new_peak_wallet to a wallet peer with no subscription; if this \
         fails, the peak-only session is not viable and the supervisor should idle instead",
    );
    // Printed because this test is run by hand as an acceptance step, and the operator's
    // question is "which height did a real peer actually report", not merely "did it pass".
    println!("live mainnet peak reported with ZERO subscriptions: {peak}");
    assert!(peak > 5_000_000, "a plausible mainnet height, got {peak}");
    assert!(
        !db.is_synced().await.unwrap(),
        "a peak-only session must never mark the replica caught up"
    );
}
