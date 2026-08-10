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
    /// What the WRITER session answers when asked for the header hash at the corroboration
    /// height. `None` means it declines. Scripted so a test can make the writer agree with the
    /// quorum, contradict it, or refuse — the three inputs `may_elevate` distinguishes.
    writer_answer: Mutex<Option<Bytes32>>,
    /// Heights the writer was asked about, in order, so a test can prove the writer never chose
    /// its own exam height.
    writer_asked_at: Mutex<Vec<u32>>,
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

    async fn header_hash_at(&self, height: u32) -> Result<Option<Bytes32>, SyncError> {
        self.script.writer_asked_at.lock().unwrap().push(height);
        Ok(*self.script.writer_answer.lock().unwrap())
    }

    async fn catch_up(
        &self,
        db: &WalletDb,
        puzzle_hashes: Vec<Bytes32>,
        genesis_challenge: Bytes32,
        events: &EventBus,
        trust: PeerTrust,
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
            // The EFFECTIVE trust the supervisor resolved, exactly as production passes it --
            // reading `self.trust` here would make the elevation invisible to the floor check and
            // quietly re-create the bug this suite exists to exclude.
            trust,
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
        Self::start_full(db, hashes, script, addrs, trust, None).await
    }

    /// Start a supervisor with an explicit corroborator — `None` reproduces the pre-#2568
    /// behaviour, where a discovered peer writes nothing.
    async fn start_full(
        db: WalletDb,
        hashes: Arc<dyn PuzzleHashSource>,
        script: Arc<Script>,
        addrs: Vec<String>,
        trust: PeerTrust,
        corroborator: Option<Arc<dyn Corroborator>>,
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
            corroborator: corroborator.clone(),
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

    /// Poll the COMPOSED status until `predicate` holds, or fail. The phase depends on live
    /// session facts that no DB row carries, so it can only be awaited through the handle.
    async fn until_status(&self, what: &str, mut predicate: impl FnMut(&WalletSyncStatus) -> bool) {
        for _ in 0..2_000 {
            if predicate(&self.handle.status(&self.db).await.unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// Wait until the supervisor has connected AND finished deciding what that session may do.
    ///
    /// Anchored on an OBSERVED event (a completed connect) rather than a bare sleep, then given a
    /// short grace for the trust decision that immediately follows it. The grace is what makes the
    /// NEGATIVE assertions ("`catch_up` was never called") meaningful: without it the test could
    /// assert zero simply by looking too early, which would pass against any implementation at
    /// all.
    async fn settle(&self) {
        self.until("a session to be established", |s| {
            s.connects.load(Ordering::SeqCst) >= 1
        })
        .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
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
/// subscribed — which is what lets an OPERATOR peer's session keep the peak current on a
/// wallet-less node. [`Harness::start`] dials as [`PeerTrust::Operator`]; a DISCOVERED peer
/// subscribes nothing AND writes nothing, so it never advances the peak (see
/// [`a_discovered_peer_never_marks_the_replica_authoritative_across_reconnects`]). The
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
        "an operator peer's nothing-subscribed session must still advance the replica peak"
    );
    assert!(
        !db.is_synced().await.unwrap(),
        "advancing the peak must NOT imply the wallet is caught up"
    );
    h.stop().await;
}

/// **Proves (#2609), end to end through the real supervisor:** a default install — an
/// authoritative peer and NO wallet enrolled — settles on `NoAddressesToWatch` rather than
/// reporting `Syncing` for ever.
///
/// The handle-level tests above set the two session facts directly, which pins the ladder but not
/// the WIRING. This one runs the actual supervisor loop over an empty custody set and asserts the
/// phase it publishes, so a fix that changed the ladder and forgot to record the facts — the
/// version that still reproduces the defect on a real machine — fails here.
#[tokio::test]
async fn a_default_install_with_no_wallet_settles_on_nothing_to_watch() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let h = Harness::start(
        db.clone(),
        Arc::new(FixedHashes(Vec::new())),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;

    h.until_status("nothing to watch", |s| {
        s.phase == SyncPhase::NoAddressesToWatch
    })
    .await;

    let status = h.handle.status(&db).await.unwrap();
    assert_eq!(
        status.watched_addresses,
        Some(0),
        "the empty custody set must be reported as a MEASURED zero, not as unknown"
    );
    assert!(
        !db.sync_state().await.unwrap().initial_sync_complete,
        "the phase must settle WITHOUT latching initial_sync_complete: latching it would flip \
         wallet-scoped reads to an un-queried local DB and read a funded wallet as empty"
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
/// The LIVENESS assertion is the control: a supervisor that satisfied the trust boundary by
/// refusing to dial discovered peers at all would leave a default install with no peer count and
/// no `syncing` phase, and would fail here. It replaces the peak assertion this test used to
/// carry — the third audit round established that the peak was never the harmless half (see
/// [`sync::PeerTrust`]), so the peak is now asserted to stay UNKNOWN instead.
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
        assert!(
            h.handle
                .status(&db)
                .await
                .unwrap()
                .chia_peer_count
                .is_some_and(|n| n >= 1),
            "cycle {cycle}: the session must still COUNT — liveness is the whole of what a \
             discovered peer contributes, so a supervisor that simply refuses to dial one fails \
             here"
        );
        let sender = h.script.senders.lock().unwrap().last().unwrap().clone();
        sender
            .send(peak_message(6_000_000 + cycle))
            .await
            .expect("the session consumes peer pushes");
        // The attacker hangs up, buying itself a reconnect. Observing the NEXT connect (the top
        // of the following iteration) is what proves the frame above was consumed first: the
        // loop only returns once its receiver closes, which happens here.
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
        None,
        "and must not have moved the peak either: three sessions pushed a new_peak_wallet each \
         and the replica's own height is still UNKNOWN"
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

/// **Proves (#2609):** an authoritative peer attached over a GENUINELY empty custody set reports
/// `NoAddressesToWatch`, not `Syncing`.
///
/// This is the default-install shape and the whole defect: with no wallet enrolled there are zero
/// puzzle hashes, so `initial_sync::catch_up` is never called, so `initial_sync_complete` can
/// never latch — while `new_peak_wallet` keeps the replica's peak advancing with the chain. The
/// old ladder mapped that to `Syncing`, and dig-app rendered "your node is still catching up",
/// which is false: there is nothing to catch up ON.
#[tokio::test]
async fn phase_is_no_addresses_to_watch_when_custody_is_empty_on_a_writing_peer() {
    let db = WalletDb::open_in_memory().await.unwrap();
    // The replica is at the tip and following it — exactly what the machine measured.
    db.set_peak(9_131_403, "aa").await.unwrap();
    assert!(
        !db.sync_state().await.unwrap().initial_sync_complete,
        "the premise: an empty custody set never latches initial_sync_complete"
    );

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_subscription(true, 0);

    let status = handle.status(&db).await.unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::NoAddressesToWatch,
        "a replica at the tip with nothing to watch is not 'catching up'"
    );
    assert_eq!(status.peak_height, Some(9_131_403));
    assert_eq!(
        status.watched_addresses,
        Some(0),
        "the reason for the phase must be machine-readable, not inferred from the word"
    );
}

/// **Proves (#2609):** a DISCOVERED peer is NOT reported as "nothing to watch", even though its
/// subscription set is also empty.
///
/// The anti-conflation guard, and the reason the phase cannot key on `nothing_subscribed`. The
/// supervisor FORCES the subscription set to empty for an uncorroborated peer, so "the set the
/// session subscribed is empty" is true in two completely different situations: custody holds
/// nothing (benign — nothing to do), and the writer was refused (NOT benign — the replica is
/// deliberately not being written and is falling behind). Reporting the second as "nothing to
/// watch" would tell a user everything was fine while their node silently stopped following the
/// chain.
#[tokio::test]
async fn a_refused_writer_is_not_reported_as_nothing_to_watch() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    // What the supervisor records for an uncorroborated session: it subscribed nothing, but it
    // subscribed nothing because it may not write — not because custody is empty.
    handle.set_subscription(false, 0);

    assert_eq!(
        handle.status(&db).await.unwrap().phase,
        SyncPhase::Syncing,
        "a peer that may not write is genuinely not synced; it must not read as 'nothing to watch'"
    );
}

/// **Proves (#2609):** the phase does not flip to `NoAddressesToWatch` on an UNMEASURED
/// subscription set.
///
/// `watched` is `Option<u32>` rather than `u32` precisely so that "we have not resolved this
/// session's set yet" cannot be spelled the same way as "we resolved it and it is empty". A
/// session spends real time in the unmeasured state — corroboration dials four peers before the
/// set is decided — and a `0` default there would announce "nothing to watch" during every single
/// connect, which is the vacuous-default shape this ecosystem keeps finding.
#[tokio::test]
async fn an_unmeasured_subscription_set_does_not_claim_nothing_to_watch() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);

    let status = handle.status(&db).await.unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::Syncing,
        "a session whose set is not yet resolved is still syncing"
    );
    assert_eq!(
        status.watched_addresses, None,
        "unmeasured must be distinguishable from measured-zero"
    );
}

/// **Proves (#2609):** a peer that DROPS does not leave its subscription facts behind.
///
/// Stale facts would let a disconnected node keep answering `watched_addresses: 0` as though a
/// session had just measured it.
#[tokio::test]
async fn dropping_a_session_clears_its_subscription_facts() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_subscription(true, 0);
    assert_eq!(
        handle.status(&db).await.unwrap().phase,
        SyncPhase::NoAddressesToWatch
    );

    handle.set_connected(0);
    let status = handle.status(&db).await.unwrap();
    assert_eq!(status.phase, SyncPhase::Syncing);
    assert_eq!(
        status.watched_addresses, None,
        "a dropped session's measurement is no longer a measurement"
    );
}

/// **Proves (#2609):** an enrolled wallet that has NOT finished its catch-up still reports
/// `Syncing`.
///
/// The new variant must not swallow the genuine catching-up case it sits next to.
#[tokio::test]
async fn an_enrolled_wallet_mid_catch_up_still_reports_syncing() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_subscription(true, 3);

    let status = handle.status(&db).await.unwrap();
    assert_eq!(status.phase, SyncPhase::Syncing);
    assert_eq!(status.watched_addresses, Some(3));
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
        // A subscribed wallet, so `slept` records ONLY the backoff ladder: a nothing-subscribed
        // session
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

/// **THE ACCEPTANCE TEST (#2568):** on a real mainnet default install — nothing in the `peers`
/// table, no configuration — a DISCOVERED peer is corroborated by an independently drawn quorum
/// and the replica peak becomes known and ADVANCES.
///
/// This is the only test that can falsify the two assumptions the whole design rests on: that
/// dialling strangers yields enough DISTINCT reachable peers to form a quorum at all, and that
/// real mainnet full nodes actually agree with each other at a settled height. Neither is
/// provable against a double, and getting either wrong means the node silently never syncs —
/// exactly the condition #2568 exists to end.
///
/// It asserts the peak ADVANCES rather than merely becoming non-null: a single write could come
/// from one lucky frame, whereas movement over the window is the replica genuinely following the
/// chain. `initial_sync_complete` is deliberately NOT asserted here, because this fixture holds no
/// wallet: with zero puzzle hashes there is nothing to catch up, and §18.6's empty-set invariant
/// correctly refuses to mark an un-queried DB authoritative. That invariant is unchanged by #2568.
///
/// Ignored because it dials mainnet; run it by hand.
#[tokio::test]
#[ignore = "dials real mainnet peers; run by hand as the #2568 acceptance step"]
async fn live_mainnet_default_install_corroborates_and_follows_the_chain() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let factory = Arc::new(ChiaPeerSessionFactory::mainnet(db.clone()));
    let (handle, join) = spawn_supervisor(Supervisor {
        db: db.clone(),
        puzzle_hashes: Arc::new(FixedHashes(vec![])),
        factory,
        events: Arc::new(EventBus::default()),
        genesis_challenge: chia_wallet_sdk::types::MAINNET_CONSTANTS.genesis_challenge,
        time: Arc::new(TokioTime),
        corroborator: Some(Arc::new(ChiaQuorumCorroborator::mainnet())),
    });

    // A mainnet block lands roughly every 19s. Corroboration itself needs several sequential
    // dials before the first write is even possible, so the window has to cover that PLUS enough
    // blocks to see movement: six minutes is ~19 peaks of margin.
    let deadline = std::time::Instant::now() + Duration::from_secs(360);
    let mut peers = None;
    let mut first_peak: Option<u32> = None;
    let mut latest_peak: Option<u32> = None;
    while std::time::Instant::now() < deadline {
        peers = handle.status(&db).await.unwrap().chia_peer_count;
        latest_peak = db.sync_state().await.unwrap().peak_height;
        if let Some(seen) = latest_peak {
            first_peak.get_or_insert(seen);
            // Movement, not merely presence: one lucky frame is not "following the chain".
            if latest_peak > first_peak {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(10), join).await;

    // Printed because this is run by hand as an acceptance step, and the operator's question is
    // "did real strangers actually corroborate each other", not merely "did it pass".
    println!("live mainnet: peers={peers:?} first_peak={first_peak:?} latest_peak={latest_peak:?}");
    assert!(
        peers.is_some_and(|n| n >= 1),
        "discovery must yield a live session; without one a default install has no liveness at \
         all. Got {peers:?}"
    );
    assert!(
        first_peak.is_some(),
        "the replica peak stayed UNKNOWN: no discovered peer was corroborated in six minutes, so \
         a default install still does not sync"
    );
    assert!(
        latest_peak > first_peak,
        "the peak was written once but never ADVANCED ({first_peak:?} -> {latest_peak:?}); the \
         replica is not following the chain"
    );
}

// ---------------------------------------------------------------------------
// T14 — the trust label itself
// ---------------------------------------------------------------------------

/// **Proves (F2, #2501):** the trust label is a total function of the DIAL SOURCE, pinned on
/// BOTH arms.
///
/// **Why this test exists at all.** The third audit round flipped the discovery call site's
/// label from `Discovered` to `Operator` — handing every stranger on the DNS introducer list the
/// authority to rewrite the replica — and all 365 dig-wallet tests stayed green. Nothing pinned
/// the mapping: [`ScriptedFactory`] takes its `trust` from the harness, so no supervisor test
/// ever observes the production label, and
/// [`user_managed_peers_are_tried_before_discovery`] asserts dial ORDER only, which the
/// inverted version satisfies exactly as well as the correct one.
///
/// **What it can and cannot catch.** It catches the mapping being inverted, widened, or made to
/// depend on anything else — the function takes no peer input, so there is no argument by which
/// a peer could influence its own label. It does NOT catch a call site passing the wrong
/// `DialSource`; that residual is why the two constructors below sit immediately beside the
/// dial they describe, where a reader can see the source and the label in one line.
#[test]
fn the_trust_label_is_fixed_by_the_dial_source() {
    assert_eq!(
        trust_for(DialSource::UserManagedPeerRow),
        PeerTrust::Operator,
        "an address the operator typed in is the ONE thing that earns write authority; a wallet \
         pointed at the operator's own full node that then refused to sync from it would be \
         useless, so this arm is as load-bearing as the other"
    );
    assert_eq!(
        trust_for(DialSource::Discovery),
        PeerTrust::Discovered,
        "a DNS-introducer answer, or whoever won the race to bind 127.0.0.1:8444, may never \
         write to wallet.sqlite"
    );
}

// ---------------------------------------------------------------------------
// Quorum-by-agreement peer trust (dig_ecosystem#2568)
// ---------------------------------------------------------------------------

/// The header hash an honest quorum agrees on at the settled height.
const HONEST_HASH: Bytes32 = Bytes32::new([0x11; 32]);
/// A different hash — what a lying writer answers instead.
const LIARS_HASH: Bytes32 = Bytes32::new([0x22; 32]);
/// The settled height a scripted corroboration round lands on.
const SETTLED_HEIGHT: u32 = 5_999_998;

/// A corroborator returning a scripted round, recording how many rounds were run.
///
/// Deliberately able to express EVERY verdict rather than just pass/fail: a double that can only
/// say yes or no cannot exhibit the difference between "the quorum split" and "the quorum agreed
/// and the writer disagreed", which are the two refusals with different meanings.
struct ScriptedCorroborator {
    round: Mutex<CorroborationRound>,
    rounds: AtomicUsize,
}

impl ScriptedCorroborator {
    fn new(verdict: Verdict<Bytes32>) -> Arc<Self> {
        Arc::new(Self {
            round: Mutex::new(CorroborationRound {
                height: SETTLED_HEIGHT,
                verdict,
            }),
            rounds: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl Corroborator for ScriptedCorroborator {
    async fn corroborate(&self) -> Result<CorroborationRound, SyncError> {
        self.rounds.fetch_add(1, Ordering::SeqCst);
        Ok(self.round.lock().unwrap().clone())
    }
}

/// Run one discovered-peer session to completion against a scripted corroborator, and report
/// what the replica ended up holding.
async fn run_discovered_session(
    verdict: Verdict<Bytes32>,
    writer_answer: Option<Bytes32>,
) -> (WalletDb, Arc<Script>) {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    *script.writer_answer.lock().unwrap() = writer_answer;
    let hashes: Arc<dyn PuzzleHashSource> = Arc::new(FixedHashes(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_full(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
        Some(ScriptedCorroborator::new(verdict)),
    )
    .await;

    harness.settle().await;
    harness.stop().await;
    (db, script)
}

/// **Proves:** a single lying peer cannot move the replica.
///
/// FIXTURE DESIGN — exactly ONE actor varies. The quorum is honest and UNANIMOUS; only the writer
/// lies. An all-hostile fixture would read as the harsher test and is precisely the one that
/// cannot see a missed check, because there would be no honest answer for the liar to be caught
/// contradicting.
///
/// TWO HOPS, because the fix is a PLACEMENT. Asserting only "the replica is empty" would be
/// satisfied identically by a guard left down inside `initial_sync_with` — the pre-#2568
/// placement — and a later refactor moving the check would keep such a test green. So this also
/// asserts `catch_up` was never CALLED. Only a guard that runs BEFORE the catch-up can satisfy
/// both, which is the property that actually matters: a peer that fails corroboration never gets
/// a window in which its answers are already landing.
#[tokio::test]
async fn a_single_lying_writer_cannot_move_the_replica() {
    let (db, script) =
        run_discovered_session(Verdict::Unanimous(HONEST_HASH), Some(LIARS_HASH)).await;

    assert_eq!(
        script.catch_up_count(),
        0,
        "the catch-up RAN for a peer that contradicted the quorum; the guard is placed after the \
         write path instead of before it"
    );
    let state = db.sync_state().await.unwrap();
    assert_eq!(
        state.peak_height, None,
        "a lying peer moved the replica peak"
    );
    assert!(!state.initial_sync_complete);
    assert!(!db.is_synced().await.unwrap());
}

/// **Proves:** the honest control — a writer that AGREES with the quorum IS elevated and does
/// sync.
///
/// Without this, every assertion above is satisfied by a node that simply never syncs anything,
/// which is the bug #2568 exists to fix. This is the acceptance property in unit form: a
/// DISCOVERED peer, no operator peer anywhere, reaching `initial_sync_complete` and a non-NULL
/// peak.
#[tokio::test]
async fn a_corroborated_discovered_peer_syncs_a_default_install() {
    let (db, script) =
        run_discovered_session(Verdict::Unanimous(HONEST_HASH), Some(HONEST_HASH)).await;

    assert!(
        script.catch_up_count() >= 1,
        "a corroborated peer never ran a catch-up, so a default install still does not sync"
    );
    let state = db.sync_state().await.unwrap();
    // Asserted on the DB, which is where coin selection will read it from -- not on the script's
    // record that a catch-up was attempted.
    assert!(state.initial_sync_complete || state.peak_height.is_some());
    let state = db.sync_state().await.unwrap();
    assert!(
        state.initial_sync_complete,
        "initial_sync_complete stayed false for a corroborated peer"
    );
    assert_eq!(
        state.peak_height,
        Some(CATCH_UP_HEIGHT),
        "the replica peak stayed unknown for a corroborated peer"
    );
}

/// **Proves:** a SPLIT answer writes nothing, and is not silently resolved by taking a side.
///
/// FIXTURE DESIGN: the writer answers the value that a plurality-taking implementation would
/// most likely settle on, so "the writer happened to be refused for some other reason" is
/// excluded — if the split were being resolved at all, this writer would agree with the result
/// and be elevated.
#[tokio::test]
async fn a_split_quorum_writes_nothing() {
    let split = Verdict::Split {
        tallies: vec![2, 2],
    };
    let (db, script) = run_discovered_session(split, Some(HONEST_HASH)).await;

    assert_eq!(
        script.catch_up_count(),
        0,
        "a split quorum was resolved by taking a side"
    );
    assert_eq!(db.sync_state().await.unwrap().peak_height, None);
}

/// **Proves:** an unreachable quorum is a refusal, not a default-allow.
///
/// NEAREST WRONG IMPLEMENTATION: treating `Insufficient` as "nobody objected". An attacker who
/// can make peers unreachable — trivial on a hostile network — would otherwise get the replica
/// by silencing the witnesses rather than by out-voting them.
#[tokio::test]
async fn an_unreachable_quorum_refuses_rather_than_defaulting_to_allow() {
    let thin = Verdict::Insufficient {
        answered: 1,
        required: quorum::QUORUM_SAMPLE,
    };
    let (db, script) = run_discovered_session(thin, Some(HONEST_HASH)).await;

    assert_eq!(script.catch_up_count(), 0);
    assert_eq!(db.sync_state().await.unwrap().peak_height, None);
}

/// **Proves:** the writer does not choose the height it is examined at.
///
/// A writer that could pick its own exam height could pick one it had prepared an answer for, so
/// the height must come from the independently drawn quorum. The fixture asserts the writer was
/// asked at exactly the round's height and nowhere else.
#[tokio::test]
async fn the_writer_is_examined_at_a_height_it_did_not_choose() {
    let (_db, script) =
        run_discovered_session(Verdict::Unanimous(HONEST_HASH), Some(HONEST_HASH)).await;

    let asked = script.writer_asked_at.lock().unwrap().clone();
    assert!(!asked.is_empty(), "the writer was never examined at all");
    assert!(
        asked.iter().all(|h| *h == SETTLED_HEIGHT),
        "the writer was asked at a height other than the quorum's settled one: {asked:?}"
    );
}

/// **Proves:** a writer that DECLINES the question is refused, exactly as one that answers wrongly
/// is.
///
/// Silence is not agreement. NEAREST WRONG IMPLEMENTATION: `writer_answer.unwrap_or(quorum_answer)`
/// or any `if let Some(..)` whose else-branch falls through to elevation.
#[tokio::test]
async fn a_writer_that_declines_the_question_is_not_elevated() {
    let (db, script) = run_discovered_session(Verdict::Unanimous(HONEST_HASH), None).await;

    assert_eq!(script.catch_up_count(), 0);
    assert_eq!(db.sync_state().await.unwrap().peak_height, None);
}

/// **Proves:** with corroboration switched OFF, a discovered peer still writes nothing — the
/// pre-#2568 behaviour is preserved exactly, so an offline or test host does not quietly gain a
/// weaker trust model.
#[tokio::test]
async fn corroboration_switched_off_leaves_a_discovered_peer_writing_nothing() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    *script.writer_answer.lock().unwrap() = Some(HONEST_HASH);
    let hashes: Arc<dyn PuzzleHashSource> = Arc::new(FixedHashes(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_full(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
        None,
    )
    .await;
    harness.settle().await;
    harness.stop().await;

    assert_eq!(script.catch_up_count(), 0);
    assert_eq!(db.sync_state().await.unwrap().peak_height, None);
}

/// **Proves:** the CORROBORATED read is what reaches spend-path coin selection — there is no
/// second, uncorroborated path underneath it.
///
/// Coin selection reads the replica, and [`routing::route`] is the gate that decides whether the
/// replica answers for money at all. That gate turns on `initial_sync_complete`, which
/// `initial_sync_with` is the only peer-reachable writer of, and which is now reachable only
/// through corroboration. So the property is expressible as: the SAME wallet, same peer, same
/// data, routes to the fallback tier when the peer was not corroborated and to the replica when it
/// was.
///
/// FIXTURE DESIGN: both halves run the identical scenario and vary ONE thing — whether the writer
/// agrees with the quorum. A test asserting only the corroborated half would pass against a
/// routing gate that always said `Db`.
#[tokio::test]
async fn only_a_corroborated_read_reaches_coin_selection() {
    // Uncorroborated: coin selection must NOT read the replica.
    let (db, _) = run_discovered_session(Verdict::Unanimous(HONEST_HASH), Some(LIARS_HASH)).await;
    assert_eq!(
        routing::route(db.is_synced().await.unwrap(), true),
        Source::Fallback,
        "an uncorroborated peer's replica was routed to for a wallet-scoped read"
    );

    // Corroborated: the same read now comes from the replica the quorum vouched for.
    let (db, _) = run_discovered_session(Verdict::Unanimous(HONEST_HASH), Some(HONEST_HASH)).await;
    assert_eq!(
        routing::route(db.is_synced().await.unwrap(), true),
        Source::Db,
        "a corroborated sync did not become the source coin selection reads"
    );
}

/// **Proves:** `may_elevate` requires BOTH a reached verdict AND the writer agreeing with it.
///
/// A pure-function table so every combination is covered, including the one a reader is most
/// likely to assume is safe: a quorum that agreed unanimously, with a writer that said something
/// else. Corroborating everyone EXCEPT the peer doing the writing is the subtle version of this
/// bug.
#[test]
fn elevation_requires_both_a_verdict_and_the_writers_agreement() {
    let reached = CorroborationRound {
        height: SETTLED_HEIGHT,
        verdict: Verdict::Unanimous(HONEST_HASH),
    };
    let split = CorroborationRound {
        height: SETTLED_HEIGHT,
        verdict: Verdict::Split {
            tallies: vec![2, 2],
        },
    };

    assert!(
        may_elevate(&reached, Some(HONEST_HASH)),
        "the honest case was refused"
    );
    assert!(!may_elevate(&reached, Some(LIARS_HASH)));
    assert!(!may_elevate(&reached, None));
    assert!(!may_elevate(&split, Some(HONEST_HASH)));
    assert!(!may_elevate(&split, None));
}
