//! Supervisor tests (dig_ecosystem#2501).
//!
//! The doubles here stop at the PEER boundary and nowhere else: `catch_up` runs the real
//! [`sync::initial_sync_with_authority`] (so the empty-set guard is genuinely in the path) and `run` runs
//! the real [`sync::run_update_loop`] (so a peak advance is a real decode + a real DB write).
//! Only the socket is fake.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use chia::protocol::{Message, NewPeakWallet, ProtocolMessageTypes, RespondPuzzleState};

use super::*;
use crate::sage::fallback::ChainPeerTier;
use crate::sage::routing::{self, Source};
use crate::sage::sync::PuzzleStateSource;

/// The session lifetime a test passes when it is NOT testing rotation.
///
/// A DISTINCTIVE value, not `SESSION_MAX_LIFETIME`: this clock returns from every sleep instantly,
/// so a timer is identifiable ONLY by the duration it asked for, and suppressing a duration
/// silences every timer that asks for it. The real lifetime once shared `BACKOFF_MAX`'s 60 seconds,
/// so suppressing it silenced backoff waits too — one in forty-one, whenever jitter landed on
/// exactly 100% — and wedged the supervisor for good. A DAY is chosen now because no production
/// timer will ever ask for one, which keeps the suppression unambiguous however the real constants
/// move; 3600s was given up because `CATCH_UP_DEADLINE` came to share it, re-creating exactly that
/// collision.
const NO_ROTATION: Duration = Duration::from_secs(86_400);

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
    /// One entry per `catch_up`, holding the EFFECTIVE authority the supervisor resolved.
    ///
    /// The ceiling has exactly one production construction site (`trust_for_session`), and until
    /// this was recorded nothing in this suite could see what it built — so mutating its anchor
    /// left every test green (dig_ecosystem#2851, A2).
    authorities: Mutex<Vec<sync::WriteAuthority>>,
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
    /// Sleep durations that NEVER return, so the timer they belong to cannot fire.
    ///
    /// This clock returns from every sleep immediately, which is what makes the backoff ladder
    /// testable in milliseconds — and which also means EVERY timer in the supervisor's `select!`
    /// fires at once. A test observing one timer must therefore silence the others, or it proves
    /// only that *something* ended the session. [`NO_ROTATION`] is silenced by default
    /// (dig_ecosystem#2851): rotation ends every session on its own, so without this the stall
    /// tests would pass against a supervisor with no stall detection at all.
    suppressed: Mutex<Vec<Duration>>,
    /// Suppressed timers that were nonetheless ARMED, so a test can still prove the supervisor
    /// asked to wait even though the wait was never allowed to finish.
    suppressed_waits: Mutex<Vec<Duration>>,
    /// When set, `catch_up` records its call and then NEVER returns — a peer that keeps a catch-up
    /// alive on a live socket, which is the state the per-round-trip timeout cannot end
    /// (dig_ecosystem#2851).
    catch_up_parks: std::sync::atomic::AtomicBool,
}

impl Script {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(Some(Instant::now())),
            // Both of the supervisor's long timers are silenced by default, for the same reason:
            // this clock returns instantly, so an unsilenced timer fires the moment it is armed and
            // every test would prove only that *something* ended the session. A test that is ABOUT
            // one of them lifts its own suppression.
            suppressed: Mutex::new(vec![NO_ROTATION, CATCH_UP_DEADLINE]),
            ..Self::default()
        })
    }

    /// Let a timer that is silenced by default actually fire — for the test that is about it.
    fn allow(&self, duration: Duration) {
        self.suppressed.lock().unwrap().retain(|d| *d != duration);
    }

    /// Make every `catch_up` hang instead of completing, modelling a peer that answers each round
    /// trip just inside its timeout and so never trips the per-round-trip bound.
    fn park_the_catch_up(&self) {
        self.catch_up_parks.store(true, Ordering::SeqCst);
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
        // Bound BEFORE the `if`: a guard created in the condition lives to the end of the whole
        // statement, so testing it inline would hold the lock across the `.await` below and wedge
        // every later sleep in the process.
        let suppressed = self.suppressed.lock().unwrap().contains(&duration);
        if suppressed {
            // Recorded SEPARATELY — `slept` is read positionally by the backoff-ladder test, and a
            // suppressed timer never elapses, so counting it there would insert a rung that no
            // backoff ever waited.
            self.suppressed_waits.lock().unwrap().push(duration);
            std::future::pending::<()>().await;
        }
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
        authority: sync::WriteAuthority,
    ) -> Result<(), SyncError> {
        self.script
            .catch_ups
            .lock()
            .unwrap()
            .push(puzzle_hashes.clone());
        self.script.authorities.lock().unwrap().push(authority);
        if self.script.catch_up_parks.load(Ordering::SeqCst) {
            // Recorded FIRST, so a test can still prove the catch-up was entered.
            std::future::pending::<()>().await;
        }
        // The REAL catch-up, so the empty-set guard and the completion-flag write are both
        // exercised exactly as production would exercise them.
        sync::initial_sync_with_authority(
            &CaughtUpAtOnce,
            db,
            puzzle_hashes,
            genesis_challenge,
            &self.peer_ip(),
            events,
            // The EFFECTIVE authority the supervisor resolved, exactly as production passes it --
            // reading `self.trust` here would make the elevation invisible to the floor check and
            // quietly re-create the bug this suite exists to exclude.
            authority,
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

    /// Hashes appearing IS the wallet appearing, for this double.
    fn any_wallet(&self) -> bool {
        !self.0.lock().unwrap().is_empty()
    }
}

/// A fixed puzzle-hash set, for tests that do not need real custody.
///
/// `enrolled` is carried SEPARATELY from the set rather than derived from it, because the state
/// this double has to be able to express is precisely the one where they disagree: an enrolled
/// wallet whose addresses are unreachable (dig_ecosystem#2609). A double that computed enrollment
/// from `is_empty()` could not represent a locked wallet at all, and the phase distinguishing them
/// would be untestable.
struct FixedHashes {
    hashes: Vec<Bytes32>,
    enrolled: bool,
}

impl FixedHashes {
    /// No wallet at all: no hashes, nothing enrolled.
    fn none() -> Self {
        Self {
            hashes: Vec::new(),
            enrolled: false,
        }
    }

    /// A wallet whose addresses ARE derivable.
    fn unlocked(hashes: Vec<Bytes32>) -> Self {
        Self {
            hashes,
            enrolled: true,
        }
    }

    /// An ENROLLED wallet the node holds no addresses for — the post-restart shape.
    fn enrolled_without_addresses() -> Self {
        Self {
            hashes: Vec::new(),
            enrolled: true,
        }
    }
}

impl PuzzleHashSource for FixedHashes {
    fn puzzle_hashes(&self) -> Vec<Bytes32> {
        self.hashes.clone()
    }

    fn any_wallet(&self) -> bool {
        self.enrolled
    }
}

/// A chain tip the TEST moves — the node's own peers, seen independently of the session.
///
/// The peak is settable rather than fixed because the property under test is a RELATIONSHIP over
/// time (the chain moved, the replica did not), and a double that could only report one height
/// could not express the healthy case that must NOT trip the deadline.
struct ScriptedChainTip {
    peak: Mutex<Option<u32>>,
    /// When set, the replica is written one block forward on every observation — a session that is
    /// genuinely keeping up. Wired through this double because the stall check samples the two
    /// heights TOGETHER, so "the replica advanced between polls" is only expressible by moving it
    /// in step with the observation.
    healthy_replica: Option<WalletDb>,
    /// When set, the replica only starts advancing once a SECOND session has been opened — so the
    /// first session genuinely stalls and the recovery genuinely belongs to its successor.
    advance_from_connect: Option<Arc<Script>>,
    /// Closes the live session after every second observation, so no single session can gather
    /// enough stall evidence on its own.
    drop_peer_every: Option<(Arc<Script>, Mutex<usize>)>,
}

impl ScriptedChainTip {
    /// Peers announcing `peak`, with a replica that never moves.
    fn at(peak: u32) -> Arc<Self> {
        Arc::new(Self {
            peak: Mutex::new(Some(peak)),
            healthy_replica: None,
            advance_from_connect: None,
            drop_peer_every: None,
        })
    }

    /// Peers that have said nothing — unobservable, which is not zero.
    fn unobservable() -> Arc<Self> {
        Arc::new(Self {
            peak: Mutex::new(None),
            healthy_replica: None,
            advance_from_connect: None,
            drop_peer_every: None,
        })
    }

    /// Peers ahead of a replica that is ADVANCING — the healthy control.
    fn ahead_of_an_advancing_replica(peak: u32, db: WalletDb) -> Arc<Self> {
        Arc::new(Self {
            peak: Mutex::new(Some(peak)),
            healthy_replica: Some(db),
            advance_from_connect: None,
            drop_peer_every: None,
        })
    }

    /// Peers ahead of a frozen replica, dropping the peer after every SECOND observation.
    ///
    /// Bounds how much stall evidence any ONE session can gather: at a 15-second poll, two polls
    /// is 30 seconds of the 90 `STALL_AFTER` needs, so a stall clock scoped to a session could
    /// never fire, and only a watch that survives the session boundary reaches the deadline.
    fn ahead_and_dropping_the_peer(peak: u32, script: Arc<Script>) -> Arc<Self> {
        Arc::new(Self {
            peak: Mutex::new(Some(peak)),
            healthy_replica: None,
            advance_from_connect: None,
            drop_peer_every: Some((script, Mutex::new(0))),
        })
    }

    /// A replica frozen under the FIRST session and advancing again under the second — the whole
    /// episode: stall, end, reconnect, recover.
    fn recovers_on_reconnect(peak: u32, db: WalletDb, script: Arc<Script>) -> Arc<Self> {
        Arc::new(Self {
            peak: Mutex::new(Some(peak)),
            healthy_replica: Some(db),
            advance_from_connect: Some(script),
            drop_peer_every: None,
        })
    }
}

#[async_trait::async_trait]
impl ChainTipObserver for ScriptedChainTip {
    async fn peers_peak(&self) -> Option<u32> {
        if let Some((script, seen)) = &self.drop_peer_every {
            let drop_now = {
                let mut seen = seen.lock().unwrap();
                *seen += 1;
                *seen % 2 == 0
            };
            if drop_now {
                script.disconnect_all();
            }
        }
        let held_back = self
            .advance_from_connect
            .as_ref()
            .is_some_and(|s| s.connects.load(Ordering::SeqCst) < 2);
        let replica_now = {
            let mut peak = self.peak.lock().unwrap();
            if self.healthy_replica.is_none() || held_back {
                return *peak;
            }
            let replica = peak.unwrap_or(1).saturating_sub(1);
            // The chain keeps moving too, so the replica stays BEHIND throughout: this control
            // isolates the advance-resets-the-clock rule from the level-heights rule beside it.
            *peak = Some(peak.unwrap_or(1) + 1);
            replica
        };
        if let Some(db) = &self.healthy_replica {
            db.set_peak(replica_now, "aa").await.unwrap();
        }
        *self.peak.lock().unwrap()
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
        // No chain-tip observer: stall detection off, which is exactly how every test written
        // before dig_ecosystem#2851 expects the supervisor to behave.
        Self::start_everything(db, hashes, script, addrs, trust, corroborator, None).await
    }

    /// Start a supervisor with stall detection attached, so a frozen replica can be observed
    /// (dig_ecosystem#2851).
    #[allow(clippy::too_many_arguments)]
    async fn start_everything(
        db: WalletDb,
        hashes: Arc<dyn PuzzleHashSource>,
        script: Arc<Script>,
        addrs: Vec<String>,
        trust: PeerTrust,
        corroborator: Option<Arc<dyn Corroborator>>,
        chain_tip: Option<Arc<dyn ChainTipObserver>>,
    ) -> Self {
        Self::start_with_lifetime(
            db,
            hashes,
            script,
            addrs,
            trust,
            corroborator,
            chain_tip,
            NO_ROTATION,
        )
        .await
    }

    /// Start a supervisor with an explicit session lifetime — for the tests that are ABOUT
    /// rotation (dig_ecosystem#2851).
    #[allow(clippy::too_many_arguments)]
    async fn start_with_lifetime(
        db: WalletDb,
        hashes: Arc<dyn PuzzleHashSource>,
        script: Arc<Script>,
        addrs: Vec<String>,
        trust: PeerTrust,
        corroborator: Option<Arc<dyn Corroborator>>,
        chain_tip: Option<Arc<dyn ChainTipObserver>>,
        session_lifetime: Duration,
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
            chain_tip,
            session_lifetime,
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
    ///
    /// The budget is three times the original 2,000, because that one was tripped by a loaded
    /// machine rather than by a real defect — and an intermittent proof is not a proof. It is not
    /// larger still because it is also the time a genuinely broken supervisor takes to FAIL, and a
    /// revert-proof that runs for seven minutes stops being run.
    async fn until(&self, what: &str, mut predicate: impl FnMut(&Script) -> bool) {
        for _ in 0..6_000 {
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
            if predicate(
                &self
                    .handle
                    .status(&self.db, ChainPeerTier::UNOBSERVABLE)
                    .await
                    .unwrap(),
            ) {
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
        Arc::new(FixedHashes::none()),
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
/// authoritative peer and NO wallet enrolled — settles on `NoWalletEnrolled` rather than
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
        Arc::new(FixedHashes::none()),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;

    h.until_status("nothing to watch", |s| {
        s.phase == SyncPhase::NoWalletEnrolled
    })
    .await;

    let status = h
        .handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
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

/// Deliver `message` to whichever session is live RIGHT NOW, retrying while sessions turn over.
///
/// A refused session is now short-lived by design (dig_ecosystem#2827), so the sender captured a
/// moment ago may already belong to a closed session. Panicking on the first closed channel would
/// make this suite flaky about a fact it is not testing; failing after the bounded retry still
/// catches a supervisor that never consumes peer pushes at all.
async fn push_peak_to_a_live_session(h: &Harness, message: Message) {
    for _ in 0..2_000 {
        let sender = h.script.senders.lock().unwrap().last().cloned();
        if let Some(sender) = sender {
            if sender.send(message.clone()).await.is_ok() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("no live session ever accepted a peer push");
}

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
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([4; 32])])),
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
        // POLLED, not sampled once. Since dig_ecosystem#2827 a refused session is deliberately
        // ended after `RECORROBORATE_AFTER` so a fresh sample can be drawn, and this suite's clock
        // returns from every sleep instantly — so the supervisor cycles connect/refuse/reconnect
        // and a single-instant read can legitimately land in a between-sessions gap. The property
        // being proven is unchanged and still load-bearing: a supervisor that refused to dial a
        // discovered peer at all would never reach a count of one, however long this polled.
        h.until_status(&format!("cycle {cycle}: the session to COUNT"), |s| {
            s.subscription_peer_count.is_some_and(|n| n >= 1)
        })
        .await;
        push_peak_to_a_live_session(&h, peak_message(6_000_000 + cycle)).await;
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
    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::Synced
    );

    handle.set_connected(0);
    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
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
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::NotStarted
    );

    handle.set_connected(1);
    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::Syncing
    );

    db.set_initial_sync_complete(true).await.unwrap();
    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::Synced
    );
}

/// **Proves (#2609):** `SyncPhase::as_wire` agrees with what serde actually puts on the wire, for
/// every variant in `ALL`.
///
/// `as_wire` is what the cross-crate conformance test compares against the published contract, so
/// if it could drift from the real serialization that test would be checking a fiction.
///
/// This test covers the SPELLING only. It does NOT establish that `ALL` is complete — an earlier
/// version of this comment claimed it did, and both pre-merge gates proved that claim false by
/// adding a variant, giving it an `as_wire` arm, and leaving `ALL` alone: every check here stayed
/// green because they all iterate `ALL` and so could not see what was missing from it. That hole
/// is now closed STRUCTURALLY rather than by assertion — `declare_sync_phases!` expands the enum,
/// `ALL` and `as_wire` from one list, so a variant absent from `ALL` cannot be written. Saying so
/// precisely matters: a gate whose rationale overstates its reach is how a gate becomes a
/// decoration.
#[test]
fn as_wire_matches_the_serialized_token_for_every_phase() {
    for phase in SyncPhase::ALL {
        let serialized = serde_json::to_string(phase).expect("a phase serializes");
        let expected = format!("\"{}\"", phase.as_wire());
        assert_eq!(
            serialized, expected,
            "as_wire disagrees with serde for {phase:?}"
        );
    }
}

/// **Proves (#2609):** an authoritative peer attached over a GENUINELY empty custody set reports
/// `NoWalletEnrolled`, not `Syncing`.
///
/// This is the default-install shape and the whole defect: with no wallet enrolled there are zero
/// puzzle hashes, so `initial_sync::catch_up` is never called, so `initial_sync_complete` can
/// never latch — while `new_peak_wallet` keeps the replica's peak advancing with the chain. The
/// old ladder mapped that to `Syncing`, and dig-app rendered "your node is still catching up",
/// which is false: there is nothing to catch up ON.
#[tokio::test]
async fn phase_is_no_wallet_enrolled_when_custody_is_empty_on_a_writing_peer() {
    let db = WalletDb::open_in_memory().await.unwrap();
    // The replica is at the tip and following it — exactly what the machine measured.
    db.set_peak(9_131_403, "aa").await.unwrap();
    assert!(
        !db.sync_state().await.unwrap().initial_sync_complete,
        "the premise: an empty custody set never latches initial_sync_complete"
    );

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    handle.set_watched(0, false);

    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::NoWalletEnrolled,
        "a replica at the tip with nothing to watch is not 'catching up'"
    );
    assert_eq!(status.peak_height, Some(9_131_403));
    assert_eq!(
        status.watched_addresses,
        Some(0),
        "the reason for the phase must be machine-readable, not inferred from the word"
    );
}

/// **Proves (#2609, the security gate's second gating finding):** an ENROLLED wallet whose
/// addresses the node cannot derive reports `WalletNotUnlocked`, NOT the all-clear.
///
/// The inputs here are byte-identical to the test above except for one bool, and that is the
/// point: an empty address set is what both states look like from inside the sync loop, and they
/// mean opposite things. The first version of this fix keyed only on the count, so a wallet whose
/// coins were not being followed reported as settled — and, worse, the SPEC then instructed every
/// consumer to render it as "there is nothing wallet-scoped to sync". That is the same falsehood
/// #2609 exists to delete, one conflation further along.
///
/// `WalletCustody::custodied_public_keys` is empty by design in four reachable states — an adopted
/// legacy seed file, a manifest predating the stored-public-keys field, a self-healed manifest, and
/// an entry whose key fails to decode — and nothing back-fills it while the wallet is locked, which
/// is the state after every restart. So this is the COMMON case, not an edge.
#[tokio::test]
async fn an_enrolled_wallet_with_no_derivable_addresses_is_not_an_all_clear() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(9_131_403, "aa").await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    // The ONLY difference from the no-wallet case above: a wallet IS enrolled.
    handle.set_watched(0, true);

    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::WalletNotUnlocked,
        "an enrolled wallet whose coins are not being followed must never read as settled"
    );
    assert_ne!(
        status.phase,
        SyncPhase::NoWalletEnrolled,
        "the two empty-set states must not collapse into one another"
    );
    assert_eq!(status.watched_addresses, Some(0));
}

/// **Proves (#2609, review finding 1):** the PRODUCTION `any_wallet()` reads the MANIFEST, not the
/// derivable key set — over a real [`WalletCustody`], not a double.
///
/// Every other locked-wallet test in this file goes through `FixedHashes`, which carries the two
/// facts independently by construction. That proves the ladder, and proves nothing about the one
/// implementation the node actually runs. The review demonstrated the gap by replacing the body of
/// `<WalletCustody as PuzzleHashSource>::any_wallet` with
/// `!PuzzleHashSource::puzzle_hashes(self).is_empty()` — the exact wrong implementation the docs
/// warn against, which makes `WalletNotUnlocked` unreachable in production and silently restores
/// the all-clear — and the whole suite stayed green at 456 passed.
///
/// The state reproduced here is real and is one of the four the security audit enumerated: a
/// SELF-HEALED manifest. `load_and_reconcile` rebuilds a missing `index.json` from the seed files
/// on disk, adopting each with `public_keys: Vec::new()`, so the wallet is enrolled while no
/// address is derivable — with nothing locked, incidentally, which is why the phase is named for
/// the observation rather than the cause.
///
/// Acceptance bar: implementing `any_wallet()` in terms of `puzzle_hashes()` MUST turn this red.
#[test]
fn production_any_wallet_reads_the_manifest_not_the_derivable_keys() {
    let dir = scratch();
    let custody = WalletCustody::mainnet(dir.clone());
    custody
        .create(&test_custody_password(), None)
        .expect("create a custodied wallet");

    // Drop the manifest so the next construction must rebuild it from the seed files alone. No
    // seed is read, written, or inspected here — only the index beside them is removed.
    let manifest = dir.join("wallets").join("index.json");
    assert!(
        manifest.exists(),
        "the fixture must have written a manifest"
    );
    std::fs::remove_file(&manifest).expect("remove the manifest");

    // A fresh custody over the same directory: seeds present, manifest rebuilt without keys.
    let healed = WalletCustody::mainnet(dir);

    assert!(
        PuzzleHashSource::puzzle_hashes(&healed).is_empty(),
        "the premise: a self-healed manifest carries no public keys, so no address is derivable"
    );
    assert!(
        PuzzleHashSource::any_wallet(&healed),
        "the wallet IS enrolled — a seed file is on disk and the manifest was rebuilt from it. \
         Sourcing this from the derivable key set would report the all-clear over a real wallet."
    );
}

/// **Proves (#2609, review finding 3):** a wallet that ALREADY completed a catch-up and is then
/// restarted LOCKED reports `WalletNotUnlocked`, never `Synced`.
///
/// The arm-ordering regression, and the nastiest case in this file because every input looks
/// healthy. `initial_sync_complete` is PERSISTENT — `db.rs` only ever clears it on a backwards
/// chain move — so it survives the restart and says "a catch-up once finished", which is true and
/// irrelevant. Meanwhile the address set is empty, because keys are not derivable while locked.
///
/// With the `Synced` arm tested first, this node reported `synced` beside `watched_addresses: 0`:
/// settled, while the user's coins were not being followed, on the most common post-restart path
/// there is. It is the same falsehood #2609 exists to remove, arriving through the one door the
/// first fix left open.
///
/// Acceptance bar: moving the `Synced` arm back above the empty-set arm MUST turn this red.
///
/// That is the WHOLE of what it pins. The peer here MAY write (`set_trust(true)`), so this test is
/// silent about a REFUSED writer — that session skips the empty-set arm on `session_may_write` and
/// still reaches `Synced` beside a measured `watched_addresses: 0` (#2666). Do not read a green
/// here as "the node can no longer report synced while watching nothing"; it cannot report it
/// *on this path*.
#[tokio::test]
async fn a_previously_synced_wallet_restarted_locked_is_not_reported_as_synced() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(9_131_403, "aa").await.unwrap();
    // The catch-up genuinely completed in an earlier run, and the flag persists across restarts.
    db.set_initial_sync_complete(true).await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    // Restarted locked: the wallet is still enrolled, its addresses are not derivable.
    handle.set_watched(0, true);

    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::WalletNotUnlocked,
        "a latched initial_sync_complete must not speak for a session watching zero addresses"
    );
    assert_ne!(
        status.phase,
        SyncPhase::Synced,
        "reporting synced while watching nothing is the exact falsehood this ticket removes"
    );
    assert_eq!(status.watched_addresses, Some(0));
}

/// **Proves (#2609):** a completed catch-up that IS watching addresses still reports `Synced`.
///
/// The control for the test above — the reordering must not swallow the legitimate synced case.
#[tokio::test]
async fn a_completed_catch_up_still_reports_synced_while_watching_addresses() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_initial_sync_complete(true).await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    handle.set_watched(3, true);

    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::Synced,
        "a wallet actually watching addresses after a completed catch-up is synced"
    );
}

/// **Proves (#2609):** the enrolled-but-unwatched state is reached through the REAL supervisor,
/// from custody's own answer, not just by setting the flag by hand.
///
/// Guards the wiring specifically: `any_wallet()` must be read from the MANIFEST rather than
/// derived from the address set. A `PuzzleHashSource` that computed enrollment as
/// `!puzzle_hashes().is_empty()` would make this state unreachable and silently restore the
/// all-clear, which is why the test double carries the two facts independently.
#[tokio::test]
async fn a_locked_wallet_reaches_wallet_not_unlocked_through_the_supervisor() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let h = Harness::start(
        db.clone(),
        Arc::new(FixedHashes::enrolled_without_addresses()),
        Script::new(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;

    h.until_status("the locked-wallet phase", |s| {
        s.phase == SyncPhase::WalletNotUnlocked
    })
    .await;

    let status = h
        .handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(status.watched_addresses, Some(0));
    assert!(
        !db.sync_state().await.unwrap().initial_sync_complete,
        "a locked wallet must not latch initial_sync_complete either"
    );
    h.stop().await;
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
    handle.set_trust(false);
    handle.set_watched(0, false);

    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::Syncing,
        "a peer that may not write is genuinely not synced; it must not read as 'nothing to watch'"
    );
}

/// **Proves (#2609):** the phase does not flip to `NoWalletEnrolled` on an UNMEASURED
/// subscription set, EVEN WHEN the attached peer may write.
///
/// This is the state the supervisor genuinely occupies between `trust_for_session` returning and
/// the subscription set being resolved, and it is the ONLY input that makes the ladder's
/// `watched == Some(0)` load-bearing: with the trust condition already satisfied, a `watched`
/// treated as `unwrap_or(0)` would announce "nothing to watch" here, on a session that has not yet
/// looked at custody. A review of the first version of this fix measured exactly that — replacing
/// `== Some(0)` with `unwrap_or(0) == 0` left the whole suite green, because the only unmeasured
/// test also left `may_write` false and was rejected a condition earlier. Hence `set_trust` and
/// `set_watched` are separate calls: the in-between state has to be reachable to be tested.
///
/// Acceptance bar for this test: `unwrap_or(0) == 0` in the ladder MUST turn it red.
#[tokio::test]
async fn a_writing_peer_with_an_unmeasured_set_does_not_claim_nothing_to_watch() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    // Trust settled; the set has NOT been resolved yet.
    handle.set_trust(true);

    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::Syncing,
        "a writing session that has not yet resolved its set has measured nothing to report"
    );
    assert_eq!(
        status.watched_addresses, None,
        "unmeasured must be distinguishable from measured-zero"
    );
}

/// **Proves (#2609):** before any trust is settled, an attached peer is still just `Syncing`.
#[tokio::test]
async fn an_unmeasured_subscription_set_does_not_claim_nothing_to_watch() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);

    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
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
    handle.set_trust(true);
    handle.set_watched(0, false);
    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::NoWalletEnrolled
    );

    handle.set_connected(0);
    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
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
    handle.set_trust(true);
    handle.set_watched(3, true);

    let status = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(status.phase, SyncPhase::Syncing);
    assert_eq!(status.watched_addresses, Some(3));
}

/// **Proves (T7, #2501):** an observed zero peers and an unobservable peer count are different
/// answers, on BOTH peer counts. A consumer must be able to tell "the supervisor is running and
/// has nobody" from "there is no supervisor to ask", and likewise "the transport holds no peers"
/// from "no transport exists to ask".
///
/// The subscription half was `chia_peer_count` until dig_ecosystem#2806 moved that name onto the
/// transport's held pool; the distinction it guards is unchanged and now has to hold twice.
#[tokio::test]
async fn both_peer_counts_distinguish_observed_zero_from_unobservable() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(42, "aa").await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    let held_none = ChainPeerTier {
        peer_count: Some(0),
        peak_height: None,
    };
    let with_supervisor = handle.status(&db, held_none).await.unwrap();
    assert_eq!(with_supervisor.subscription_peer_count, Some(0));
    assert_eq!(with_supervisor.chia_peer_count, Some(0));

    // A supervisor is running and holds nobody, yet the transport is unreachable: the two counts
    // are independent, so a status must be able to say "observed zero" for one and "unknown" for
    // the other in the SAME answer.
    let unmeasured_transport = handle
        .status(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(unmeasured_transport.subscription_peer_count, Some(0));
    assert_eq!(unmeasured_transport.chia_peer_count, None);

    let without = status_without_supervisor(&db, ChainPeerTier::UNOBSERVABLE)
        .await
        .unwrap();
    assert_eq!(without.subscription_peer_count, None);
    assert_eq!(without.chia_peer_count, None);
    assert_eq!(
        without.peak_height,
        Some(42),
        "the DB's peak stays honest without a supervisor"
    );

    // Chain sync switched off does not mean the node holds no peers: the transport is a separate
    // thing and its count survives the supervisor's absence.
    let held_five = ChainPeerTier {
        peer_count: Some(5),
        peak_height: Some(9_139_211),
    };
    let transport_only = status_without_supervisor(&db, held_five).await.unwrap();
    assert_eq!(transport_only.chia_peer_count, Some(5));
    assert_eq!(transport_only.chia_peer_peak_height, Some(9_139_211));
    assert_eq!(transport_only.subscription_peer_count, None);
}

/// **Proves (#2827):** `chia_peer_count` is what the node HOLDS at that moment, never a target it
/// is aiming at. A user reading it is reading a measurement.
///
/// Corroboration now dials up to `QUORUM_DIAL_WIDE` and asks `QUORUM_HOLD`, and neither number
/// may leak into this figure — reporting an intention as a holding is the exact defect #2806
/// corrected, and widening the dial is a fresh chance to reintroduce it.
///
/// FIXTURE DESIGN: the held count is THREE — distinct from the floor, the hold, the dial width and
/// the old sample size — so any implementation that substituted a constant for the measurement is
/// caught whichever constant it chose.
///
/// BOTH status paths are exercised, and that is not thoroughness for its own sake. The field is
/// populated in TWO places — `SyncHandle::status` and `status_without_supervisor` — so a test
/// through one of them cannot see a target substituted in the other. A mutation proved it: quoting
/// `QUORUM_HOLD` in the with-supervisor path left this test green while it covered only the other.
#[tokio::test]
async fn the_reported_chia_peer_count_is_the_held_pool_never_a_dial_target() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let held_three = ChainPeerTier {
        peer_count: Some(3),
        peak_height: Some(9_141_711),
    };

    let (handle, _rx) = SyncHandle::new();
    let attached = handle.status(&db, held_three).await.unwrap();
    let detached = status_without_supervisor(&db, held_three).await.unwrap();

    for (path, status) in [("with a supervisor", attached), ("without one", detached)] {
        assert_eq!(
            status.chia_peer_count,
            Some(3),
            "{path}: the reported peer count was not the measured holding"
        );
        for target in [
            quorum::CORROBORATION_FLOOR,
            quorum::QUORUM_HOLD,
            quorum::QUORUM_DIAL_WIDE,
        ] {
            assert_ne!(
                status.chia_peer_count,
                Some(target as u32),
                "{path}: a corroboration target ({target}) was reported as a holding"
            );
        }
    }
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
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .peak_height,
        None,
        "an un-synced replica must report an UNKNOWN peak, not a borrowed one"
    );

    db.set_peak(6_000_001, "aa").await.unwrap();
    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .peak_height,
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
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([4; 32])])),
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
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([5; 32])])),
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
        Arc::new(FixedHashes::none()),
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

    let h = Harness::start(db, Arc::new(FixedHashes::none()), script, addrs).await;
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
        puzzle_hashes: Arc::new(FixedHashes::none()),
        factory,
        events: Arc::new(EventBus::default()),
        genesis_challenge: chia_wallet_sdk::types::MAINNET_CONSTANTS.genesis_challenge,
        time: Arc::new(TokioTime),
        corroborator: Some(Arc::new(ChiaQuorumCorroborator::mainnet())),
        // The acceptance step watches a REAL peer follow mainnet; a stall deadline would only
        // add a second reason for the session to end and blur what the run proves.
        chain_tip: None,
        session_lifetime: SESSION_MAX_LIFETIME,
    });

    // A mainnet block lands roughly every 19s. Corroboration itself needs several sequential
    // dials before the first write is even possible, so the window has to cover that PLUS enough
    // blocks to see movement: six minutes is ~19 peaks of margin.
    let deadline = std::time::Instant::now() + Duration::from_secs(360);
    let mut peers = None;
    let mut first_peak: Option<u32> = None;
    let mut latest_peak: Option<u32> = None;
    while std::time::Instant::now() < deadline {
        peers = handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .chia_peer_count;
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

/// A FULL round in which every peer asked agreed — the ordinary healthy case.
///
/// The `agreed` count is the whole hold, so a thin round (`agreed: CORROBORATION_FLOOR`) is a
/// visibly different fixture rather than the same one under another name.
fn unanimous(answer: Bytes32) -> Verdict<Bytes32> {
    Verdict::Unanimous {
        answer,
        agreed: quorum::QUORUM_HOLD,
    }
}

/// A corroborator returning a scripted round, recording how many rounds were run.
///
/// Deliberately able to express EVERY verdict rather than just pass/fail: a double that can only
/// say yes or no cannot exhibit the difference between "the quorum split" and "the quorum agreed
/// and the writer disagreed", which are the two refusals with different meanings.
struct ScriptedCorroborator {
    round: Mutex<CorroborationRound>,
    rounds: AtomicUsize,
    /// The verdict every round AFTER the first returns, when it differs from the first.
    ///
    /// A double that can only answer the same way for ever cannot express the one property that
    /// distinguishes per-session corroboration from a verdict resolved once and reused: a quorum
    /// that agreed and then, on an independently drawn sample, did not.
    subsequent: Mutex<Option<Verdict<Bytes32>>>,
}

impl ScriptedCorroborator {
    fn new(verdict: Verdict<Bytes32>) -> Arc<Self> {
        Arc::new(Self {
            round: Mutex::new(CorroborationRound {
                height: SETTLED_HEIGHT,
                verdict,
            }),
            rounds: AtomicUsize::new(0),
            subsequent: Mutex::new(None),
        })
    }

    /// A quorum that corroborates the writer once and then splits on every later sample.
    fn corroborating_once_then_splitting(answer: Bytes32) -> Arc<Self> {
        let corroborator = Self::new(unanimous(answer));
        *corroborator.subsequent.lock().unwrap() = Some(Verdict::Split {
            tallies: vec![2, 2],
        });
        corroborator
    }

    fn rounds(&self) -> usize {
        self.rounds.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Corroborator for ScriptedCorroborator {
    async fn corroborate(&self) -> Result<CorroborationRound, SyncError> {
        let previous = self.rounds.fetch_add(1, Ordering::SeqCst);
        let mut round = self.round.lock().unwrap().clone();
        if previous > 0 {
            if let Some(later) = self.subsequent.lock().unwrap().clone() {
                round.verdict = later;
            }
        }
        Ok(round)
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
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

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
/// satisfied identically by a guard left down inside `initial_sync_with_authority` — the pre-#2568
/// placement — and a later refactor moving the check would keep such a test green. So this also
/// asserts `catch_up` was never CALLED. Only a guard that runs BEFORE the catch-up can satisfy
/// both, which is the property that actually matters: a peer that fails corroboration never gets
/// a window in which its answers are already landing.
#[tokio::test]
async fn a_single_lying_writer_cannot_move_the_replica() {
    let (db, script) = run_discovered_session(unanimous(HONEST_HASH), Some(LIARS_HASH)).await;

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
    let (db, script) = run_discovered_session(unanimous(HONEST_HASH), Some(HONEST_HASH)).await;

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

/// **Proves (#2827):** a round only two peers answered still syncs the replica, so the wallet
/// does not freeze because one peer of five was slow.
///
/// This is the user-visible defect: a replica held at height 9,139,211 for hours, five peers
/// connected, the chain ~2,500 blocks ahead. The datum carries its own confidence (`agreed: 2`)
/// instead of being discarded for arriving with less of it.
///
/// FIXTURE DESIGN: identical in every respect to `a_corroborated_discovered_peer_syncs_a_default
/// _install` EXCEPT the answer count, so a failure here can only be the count. The writer agrees,
/// so the round's only unusual property is its thinness.
///
/// NEAREST WRONG IMPLEMENTATION: a second confidence gate at the supervisor —
/// `round.verdict.agreed() >= QUORUM_SAMPLE` — which would leave `tally` correct and the wallet
/// frozen exactly as before. Only a fixture whose `agreed` is BELOW that and whose verdict is
/// nonetheless authoritative can see it.
#[tokio::test]
async fn a_round_only_two_peers_answered_still_syncs_the_replica() {
    let thin = Verdict::Unanimous {
        answer: HONEST_HASH,
        agreed: quorum::CORROBORATION_FLOOR,
    };
    let (db, script) = run_discovered_session(thin, Some(HONEST_HASH)).await;

    assert!(
        script.catch_up_count() >= 1,
        "a round corroborated by two peers ran no catch-up, so the replica stays frozen"
    );
    let state = db.sync_state().await.unwrap();
    assert!(
        state.initial_sync_complete,
        "initial_sync_complete stayed false for a thin but corroborated round"
    );
    assert_eq!(state.peak_height, Some(CATCH_UP_HEIGHT));
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
        required: quorum::CORROBORATION_FLOOR,
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
    let (_db, script) = run_discovered_session(unanimous(HONEST_HASH), Some(HONEST_HASH)).await;

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
    let (db, script) = run_discovered_session(unanimous(HONEST_HASH), None).await;

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
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

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

/// **Proves (dig_ecosystem#2827):** a REFUSED session ends by itself, so the reconnect path draws
/// a fresh corroboration sample — WITHOUT the peer ever disconnecting.
///
/// THE BUG THIS PINS. Corroboration ran exactly once, at session start. A round that did not
/// elevate left the session `Discovered`, which forced an EMPTY subscription set, which made
/// `await_puzzle_hashes`'s poll condition false, which left `std::future::pending()` in that
/// `select!` arm. The only remaining exit was the peer disconnecting — and a stable peer never
/// does. A node therefore parked on a peer it could never write from for the life of the process:
/// the user's replica sat at height 9,139,211 for hours while the chain moved ~2,500 blocks and
/// their wallet showed no balance. Its own log line promised "re-drawing a fresh sample" while no
/// second sample was ever drawn.
///
/// FIXTURE DESIGN — the peer is deliberately HEALTHY and stays connected for the whole test.
/// `disconnect_all` is never called, because the disconnect is the one exit the broken code
/// already had: a fixture that dropped the peer would pass against the defect and prove nothing.
/// The only variable is the passage of time on the injected clock, which is exactly the mechanism
/// under test. Corroboration is scripted to SPLIT — a refusal that is not the writer's fault and
/// that a fresh sample could plausibly resolve, which is the real shape of the user's incident.
///
/// The clock is a double whose `sleep` returns at once, so the assertion is "a second session was
/// opened", never "45 seconds elapsed" — this is a state-machine test, not a network test.
#[tokio::test]
async fn a_refused_session_ends_so_a_fresh_sample_is_drawn_without_a_disconnect() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    // The writer agrees with nothing in particular; the round SPLITS, so nobody is elevated.
    *script.writer_answer.lock().unwrap() = Some(HONEST_HASH);
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));
    let corroborator = ScriptedCorroborator::new(Verdict::Split {
        tallies: vec![2, 2],
    });

    let harness = Harness::start_full(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
        Some(corroborator.clone()),
    )
    .await;

    // TWO facts, and the second is the one that matters. A second CONNECT proves the refused
    // session ended on its own; a second corroboration ROUND proves the retry actually re-ran the
    // check rather than reconnecting into the same settled verdict.
    harness
        .until("a refused session to end and reconnect", |s| {
            s.connects.load(Ordering::SeqCst) >= 2
        })
        .await;
    assert!(
        corroborator.rounds.load(Ordering::SeqCst) >= 2,
        "the session reconnected without re-running corroboration, so the promised fresh sample is \
         still never drawn"
    );

    harness.stop().await;
}

/// **Proves (dig_ecosystem#2827):** the re-corroboration timer does NOT touch an AUTHORITATIVE
/// session — the control that keeps the fix from becoming a different bug.
///
/// An elevated session holds a live subscription, and a subscription is per-connection state.
/// Ending one on a timer would throw away a working writer every 45 seconds and re-run a catch-up
/// from genesis each time, which is a worse failure than the one being fixed.
///
/// FIXTURE DESIGN — this is the SAME harness as the test above with ONE variable changed: the peer
/// is operator-chosen, so it is authoritative and subscribes a non-empty set. The injected clock
/// returns from every sleep immediately, so an implementation that armed the timer regardless of
/// trust would reconnect in a tight loop and be caught here within milliseconds; nothing in this
/// test depends on 45 seconds being long.
#[tokio::test]
async fn an_authoritative_session_is_not_ended_by_the_recorroboration_timer() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_with_trust(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
    )
    .await;

    harness.settle().await;
    // Give the (instant) clock ample opportunity to fire a timer that should not exist.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        script.connects.load(Ordering::SeqCst),
        1,
        "an authoritative session was torn down by the re-corroboration timer, discarding a live \
         subscription and forcing a catch-up from genesis"
    );

    harness.stop().await;
}

// ---------------------------------------------------------------------------
// The stall deadline (dig_ecosystem#2851)
// ---------------------------------------------------------------------------

/// The replica peak measured on the live 0.116.0 service while it reported `synced`.
const FROZEN_REPLICA_PEAK: u32 = 9_142_861;
/// What that node's OWN five peers announced at the same moment — 57 blocks ahead, and growing.
const PEERS_PEAK: u32 = 9_142_918;

/// **Proves (dig_ecosystem#2851):** an AUTHORITATIVE session whose peer goes silent while the chain
/// advances is ENDED, and the supervisor reconnects.
///
/// THE BUG THIS PINS. `run_update_loop` waits on `recv()` with no deadline, so a half-open peer
/// connection parks it for ever. For an authoritative subscribed session every other arm of the
/// supervisor's `select!` is disarmed by construction — the resubscribe poll is armed only while
/// nothing is subscribed, `await_recorroboration` only for a refused session — leaving a disconnect
/// that never comes as the sole exit. The measured result was a replica frozen at
/// [`FROZEN_REPLICA_PEAK`] while peers advanced past [`PEERS_PEAK`].
///
/// FIXTURE DESIGN — the peer is HEALTHY at the socket level and stays connected for the whole test:
/// `disconnect_all` is never called, because a disconnect is the one exit the broken code already
/// had, and a fixture that dropped the peer would pass against the defect. The single variable is
/// that the chain is observed to move while the replica does not. Bounded by `until`'s real-time
/// budget so the pre-fix failure is a LOUD timeout rather than a hang indistinguishable from a dead
/// process.
#[tokio::test]
async fn a_stalled_authoritative_session_is_ended_and_reconnects() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_everything(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        Some(ScriptedChainTip::at(PEERS_PEAK)),
    )
    .await;

    harness
        .until("the stalled session to end and reconnect", |s| {
            s.connects.load(Ordering::SeqCst) >= 2
        })
        .await;

    harness.stop().await;
}

/// Collects everything logged on the calling thread, so a test can assert a diagnostic actually
/// reached the sink rather than trusting that it was written.
///
/// # Why ONE process-wide subscriber, and not a scoped one per test
///
/// The obvious fixture — `tracing::subscriber::set_default` per test — LOSES LINES, and loses them
/// one callsite at a time. A callsite's [`tracing::subscriber::Interest`] is resolved the first time
/// that source line executes and is then cached PROCESS-WIDE. Scoped subscribers do not participate
/// in that resolution, so whichever test reaches `warn!("… has not advanced …")` first — and
/// several stall tests reach it with no subscriber installed — cached that ONE line as disabled for
/// the rest of the binary, while every other line kept working.
///
/// That is not a theory. Under the scoped fixture, a capture was observed holding the recovery
/// `INFO` while MISSING the stall `WARN` that the same task had emitted microseconds earlier on the
/// same thread — three failures in ten full-module runs, always on a `warn!` assertion. A fixture
/// that can miss a line production really wrote can equally pass while production wrote nothing, so
/// it was unsound in both directions and no amount of retrying would have fixed it.
///
/// Installing one real subscriber for the whole binary means interest is always resolved against a
/// subscriber that says yes, and [`tracing::callsite::rebuild_interest_cache`] repairs any callsite
/// that was already cached off before the first capture test ran. Isolation then comes from the
/// SINK rather than from the dispatcher: events land in the calling thread's installed buffer, and
/// a thread that installed none discards them, so concurrent tests cannot write into each other.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

thread_local! {
    /// The buffer this thread's events are appended to, if it installed one.
    static CAPTURE_SINK: std::cell::RefCell<Option<Arc<Mutex<Vec<u8>>>>> =
        const { std::cell::RefCell::new(None) };
}

impl Capture {
    /// Route this thread's log events into this capture until the returned guard is dropped.
    ///
    /// Installs the process-wide subscriber on first use. A test's supervisor task must be polled
    /// on the installing thread for its lines to land here — which `#[tokio::test]`'s
    /// current-thread runtime guarantees, and which every caller then CHECKS rather than assumes
    /// via [`Capture::assert_saw_the_supervisor`].
    fn install(&self) -> CaptureGuard {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(ThreadSink)
                    .with_ansi(false)
                    .with_max_level(tracing::Level::TRACE)
                    .finish(),
            );
            // Repairs every callsite that was already resolved — against no subscriber, and so as
            // disabled — by a test that ran before this one.
            tracing::callsite::rebuild_interest_cache();
        });
        CAPTURE_SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&self.0)));
        CaptureGuard
    }

    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    /// Fail LOUDLY if the supervisor's own lines never reached this capture.
    ///
    /// The positive control for the one assumption the fixture still makes — that the supervisor
    /// task is polled on the installing thread. Without it, a future runtime-flavour change would
    /// turn every assertion here into a claim about an empty buffer, which is the failure mode this
    /// fixture was rewritten to abolish rather than to relocate.
    fn assert_saw_the_supervisor(&self) {
        let log = self.contents();
        assert!(
            log.contains("wallet sync:"),
            "the capture saw NOTHING from the supervisor, so every assertion below would be about \
             an empty buffer rather than about production: {log}"
        );
    }
}

/// Detaches the calling thread's capture on drop.
struct CaptureGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURE_SINK.with(|sink| *sink.borrow_mut() = None);
    }
}

/// The process-wide writer: appends to whatever buffer the emitting thread installed.
struct ThreadSink;

/// A borrowed handle on one thread's capture buffer. `None` discards, so a thread with no capture
/// installed logs into nothing instead of into somebody else's assertions.
struct ThreadWriter(Option<Arc<Mutex<Vec<u8>>>>);

impl std::io::Write for ThreadWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(buffer) = &self.0 {
            buffer.lock().unwrap().extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadSink {
    type Writer = ThreadWriter;
    fn make_writer(&'a self) -> Self::Writer {
        ThreadWriter(CAPTURE_SINK.with(|sink| sink.borrow().clone()))
    }
}

/// **Proves (dig_ecosystem#2851):** the WHOLE episode is greppable from the log in one pass — the
/// stall names its reason and both heights, and the RECOVERY says the replica is moving again.
///
/// This is the on-host acceptance evidence, not decoration. An operator who blackholes the peer's
/// traffic sees a warning and then, without the second line, silence — which is indistinguishable
/// from the failure itself, because silence is exactly what this defect hid behind for two hours.
/// The recovery is deliberately reported by the SUCCESSOR session: the session that stalls cannot
/// observe its own recovery, so the fact has to survive its end.
///
/// FIXTURE DESIGN — the chain-tip double holds the replica still until a SECOND session exists, so
/// the first session genuinely stalls on positive evidence and the recovery genuinely belongs to
/// its successor. A double that advanced from the start would log a recovery that was never owed.
///
/// The two lines are awaited and asserted SEPARATELY, in the order production emits them. Awaiting
/// only the recovery and then asserting the stall reads as one check but is two, and the wait can
/// be satisfied while the stall line is absent — which is exactly how a lost line surfaced as a
/// baffling assertion failure instead of as a named instrument fault. The stall line needs no wait
/// of its own: `await_stall` emits it synchronously BEFORE returning, so a second connect already
/// implies it.
#[tokio::test]
async fn a_stall_and_its_recovery_are_both_named_in_the_log() {
    let capture = Capture::default();
    let guard = capture.install();

    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_everything(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        Some(ScriptedChainTip::recovers_on_reconnect(
            PEERS_PEAK,
            db,
            script.clone(),
        )),
    )
    .await;

    // Waited on OBSERVABLE STATE, not on the log. With rotation silenced and the peer never
    // disconnected, a second connect can only come from the stall arm, and a third only after the
    // successor session has been observing long enough to see the replica move again. Polling the
    // log text instead makes the wait depend on how promptly a writer flushes under load, which is
    // not the property and turns a real proof into an intermittent one.
    harness
        .until("the stalled session to end", |s| {
            s.connects.load(Ordering::SeqCst) >= 2
        })
        .await;
    // Checked HERE, before anything else is awaited: the session ended, so the warning that ends it
    // has already been written, and a capture missing it is an instrument fault rather than a
    // production one. Asserting it after the recovery wait would have blamed the wrong thing.
    capture.assert_saw_the_supervisor();
    assert!(
        capture.contents().contains("has not advanced"),
        "the stall itself must be named: {}",
        capture.contents()
    );

    harness
        .until(
            "the successor session to observe the replica advancing",
            |_| capture.contents().contains("advancing again"),
        )
        .await;

    let log = capture.contents();
    harness.stop().await;
    drop(guard);

    assert!(
        log.contains("has not advanced"),
        "the stall itself must be named: {log}"
    );
    assert!(
        log.contains("advancing again"),
        "the recovery must be named, or the log shows a failure and then silence: {log}"
    );

    // Both heights and the elapsed stall, because "the replica is behind" without numbers cannot
    // be checked against the chain by the operator reading it.
    assert!(
        log.contains("replica_peak"),
        "the stall must name the replica's peak: {log}"
    );
    assert!(
        log.contains("peers_peak"),
        "the stall must name the peers' peak: {log}"
    );
    assert!(
        log.contains("stalled_for_secs"),
        "the stall must say how long it lasted: {log}"
    );
    assert!(
        log.contains("203.0.113.1:8444"),
        "both lines must name the peer the episode was about: {log}"
    );
}

/// **Proves (dig_ecosystem#2851):** a replica that is ADVANCING is never ended, however far behind
/// its peers it happens to be.
///
/// The control that keeps the deadline from becoming a different bug. Catching up from genesis is
/// a legitimate state in which the replica trails its peers by millions of blocks for a long time,
/// and tearing that session down would restart the very work it is doing.
#[tokio::test]
async fn an_advancing_replica_is_never_declared_stalled() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_everything(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        Some(ScriptedChainTip::ahead_of_an_advancing_replica(
            PEERS_PEAK, db,
        )),
    )
    .await;

    harness.settle().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        script.connects.load(Ordering::SeqCst),
        1,
        "a replica that is visibly catching up was torn down as stalled"
    );

    harness.stop().await;
}

/// **Proves (dig_ecosystem#2851):** an UNOBSERVABLE peers' peak never declares a stall.
///
/// A missing measurement must not be spent as evidence against the replica. A node whose chain
/// transport has not been built genuinely reports `None` here, and reading that as "the chain
/// advanced past us" would end a perfectly good session every 90 seconds for ever.
#[tokio::test]
async fn an_unobservable_peers_peak_is_never_an_accusation() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_everything(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        Some(ScriptedChainTip::unobservable()),
    )
    .await;

    harness.settle().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        script.connects.load(Ordering::SeqCst),
        1,
        "a session was ended on the strength of a height nobody measured"
    );

    harness.stop().await;
}

/// **Proves (dig_ecosystem#2851):** a replica LEVEL with its peers is never declared stalled.
///
/// A quiet chain produces exactly this: nothing moves, on either side, for as long as no block is
/// found. Standing still is only evidence of a stall when something else demonstrably moved.
///
/// The peers are pinned at [`CATCH_UP_HEIGHT`] rather than at the incident's numbers because that
/// is the height the scripted catch-up actually leaves in the replica — a fixture whose two sides
/// were never level would exercise the stalled path and prove nothing about this one.
#[tokio::test]
async fn a_replica_level_with_its_peers_is_never_declared_stalled() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_everything(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        Some(ScriptedChainTip::at(CATCH_UP_HEIGHT)),
    )
    .await;

    harness.settle().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        script.connects.load(Ordering::SeqCst),
        1,
        "a quiet chain was mistaken for a frozen replica"
    );

    harness.stop().await;
}

/// **REGRESSION (dig_ecosystem#2827, guarded here for #2851):** a REFUSED session still ends by
/// itself, with a chain-tip observer attached.
///
/// The stall arm is armed only for authoritative sessions, and #2827's exit is armed only for
/// refused ones — mutually exclusive by construction. This pins that the new arm did not disturb
/// the old exit on the very path where both are present in the same `select!`. A refused session
/// writes nothing and so can NEVER advance the replica, which is exactly why arming the stall check
/// there would fire every time and fight this timer.
#[tokio::test]
async fn a_refused_session_still_ends_with_a_chain_tip_observer_attached() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();
    let script = Script::new();
    *script.writer_answer.lock().unwrap() = Some(HONEST_HASH);
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));
    let corroborator = ScriptedCorroborator::new(Verdict::Split {
        tallies: vec![2, 2],
    });

    let harness = Harness::start_everything(
        db.clone(),
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
        Some(corroborator.clone()),
        Some(ScriptedChainTip::at(PEERS_PEAK)),
    )
    .await;

    harness
        .until("a refused session to end and reconnect", |s| {
            s.connects.load(Ordering::SeqCst) >= 2
        })
        .await;
    assert!(
        corroborator.rounds.load(Ordering::SeqCst) >= 2,
        "the refused session's re-corroboration exit was disturbed by the stall arm"
    );

    harness.stop().await;
}

// ---------------------------------------------------------------------------
// Session rotation (dig_ecosystem#2851)
// ---------------------------------------------------------------------------

/// **Proves (dig_ecosystem#2851):** a session is RETIRED at its lifetime and a fresh peer is
/// dialled, even though nothing about it failed.
///
/// Holding one peer for the life of the process makes that peer the single point of both failure
/// and observation, which is how a silent peer went unnoticed for two hours.
///
/// FIXTURE DESIGN — the peer is perfectly healthy and never disconnects (`disconnect_all` is never
/// called), so a reconnect can only come from the rotation timer. This is the ONE test family that
/// lets that timer fire; every other test passes [`NO_ROTATION`], because a clock that returns
/// instantly fires every timer at once and a rotation would otherwise answer for whatever property
/// the test believed it was proving.
#[tokio::test]
async fn a_healthy_session_is_retired_at_its_lifetime() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_with_lifetime(
        db,
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        None,
        SESSION_MAX_LIFETIME,
    )
    .await;

    harness
        .until("the session to be retired and replaced", |s| {
            s.connects.load(Ordering::SeqCst) >= 3
        })
        .await;

    harness.stop().await;
}

/// **Proves (dig_ecosystem#2851):** rotation does NOT climb the backoff ladder.
///
/// A rotation is a planned end, not a failure. If it fed the ladder, a node would rotate itself
/// onto a 60-second reconnect delay within minutes and spend most of its life holding no
/// subscription at all — strictly worse than never rotating.
///
/// The assertion reads the delays the supervisor actually waited: every one must stay at the
/// ladder's first rung. `HEALTHY_SESSION` is deliberately NOT relied on to produce that: it would
/// currently agree, since a 600-second session clears its 60-second threshold, but that is
/// arithmetic between two constants either of which is free to move, and the property under test is
/// that a PLANNED end resets the ladder — not that a long one happens to.
#[tokio::test]
async fn rotation_does_not_climb_the_backoff_ladder() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    let hashes: Arc<dyn PuzzleHashSource> =
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])]));

    let harness = Harness::start_with_lifetime(
        db,
        hashes,
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        None,
        SESSION_MAX_LIFETIME,
    )
    .await;

    harness
        .until("several rotations", |s| {
            s.connects.load(Ordering::SeqCst) >= 5
        })
        .await;

    let waited: Vec<Duration> = script
        .slept
        .lock()
        .unwrap()
        .iter()
        .copied()
        .filter(|d| *d != SESSION_MAX_LIFETIME)
        .collect();
    harness.stop().await;
    // NO backoff wait at all, which is strictly stronger than "the delays stayed small" — and it is
    // the only form of this assertion that can FAIL. A rotation falling through to the ordinary
    // `Ended` path would reset the ladder anyway via `HEALTHY_SESSION`, because a 600-second session
    // is trivially older than 60 — so an assertion about the SIZE of the delays passes against both
    // implementations and proves nothing. Only the immediate `continue` produces none.
    assert!(
        waited.is_empty(),
        "a rotation went through the backoff path instead of reconnecting at once: {waited:?}"
    );
}

/// **Proves (dig_ecosystem#2851):** stall evidence SURVIVES the end of a session, so a replica that
/// freezes across several short sessions is still detected.
///
/// The property that makes the watch's placement load-bearing. Sessions end for many reasons —
/// a rotation, a disconnect, a refusal — and a stall clock scoped to ONE session restarts at every
/// one of them. A replica that is frozen the whole time would then never reach [`STALL_AFTER`], the
/// detector would be dead code that reads as a working guard, and every freeze would be cleared
/// silently with nothing logged. This test is what stops a future refactor from scoping the watch
/// back down into the session.
///
/// FIXTURE DESIGN — the chain-tip double drops the peer after every SECOND observation, so no
/// session can gather more than 30 seconds of the 90 the deadline needs. That bound is the whole
/// fixture: with a per-session clock the stall is UNREACHABLE here, and with the shared one it
/// arrives after a few sessions. The peer is dropped rather than rotated because the property is
/// "the watch outlives a SESSION", and which mechanism ended the session is immaterial to it —
/// while [`Script`]'s instantly-returning clock cannot order a rotation against a poll at all.
#[tokio::test]
async fn stall_evidence_survives_the_end_of_a_session() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    let capture = Capture::default();
    let guard = capture.install();

    let harness = Harness::start_everything(
        db,
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])])),
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Operator,
        None,
        Some(ScriptedChainTip::ahead_and_dropping_the_peer(
            PEERS_PEAK,
            script.clone(),
        )),
    )
    .await;

    harness
        .until(
            "the stall to be named despite the sessions turning over",
            |_| capture.contents().contains("has not advanced"),
        )
        .await;

    harness.stop().await;
    capture.assert_saw_the_supervisor();
    let log = capture.contents();
    drop(guard);
    assert!(
        script.connects.load(Ordering::SeqCst) >= 3,
        "the fixture must actually turn sessions over, or it proves nothing about surviving one"
    );
    assert!(
        log.contains("has not advanced"),
        "a freeze spanning several sessions went unreported: {log}"
    );
}

// ---------------------------------------------------------------------------
// The phase must be about NOW (dig_ecosystem#2851)
// ---------------------------------------------------------------------------

/// A peer tier reporting five peers at `peak` — the shape the live incident reported.
fn tier_at(peak: u32) -> ChainPeerTier {
    ChainPeerTier {
        peer_count: Some(5),
        peak_height: Some(peak),
    }
}

/// **Proves (dig_ecosystem#2851):** a completed catch-up whose replica has fallen behind its own
/// peers reports `Syncing`, not `Synced`.
///
/// Pinned with the REAL measured numbers. `initial_sync_complete` is a latched flag about the past
/// and a peer count says only that a socket exists; neither is about NOW, so both were satisfied by
/// a frozen replica and the node told every client that a 57-block-stale balance was settled.
#[tokio::test]
async fn a_replica_behind_its_peers_is_not_reported_as_synced() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_initial_sync_complete(true).await.unwrap();
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    handle.set_watched(1, true);

    let status = handle.status(&db, tier_at(PEERS_PEAK)).await.unwrap();
    assert_eq!(
        status.phase,
        SyncPhase::Syncing,
        "a replica 57 blocks behind its own peers was reported as settled"
    );
    // The measurements themselves are unchanged — only the claim made about them.
    assert_eq!(status.peak_height, Some(FROZEN_REPLICA_PEAK));
    assert_eq!(status.chia_peer_peak_height, Some(PEERS_PEAK));
    assert_eq!(status.watched_addresses, Some(1));
}

/// **Proves (dig_ecosystem#2851):** the tolerance boundary, from BOTH sides.
///
/// A bound tested only from below can only confirm itself. Exactly at
/// [`FOLLOWING_TOLERANCE`] the node is still following the chain; one block beyond it is not.
#[tokio::test]
async fn the_following_tolerance_holds_at_the_bound_and_fails_one_beyond_it() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_initial_sync_complete(true).await.unwrap();
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    handle.set_watched(1, true);

    let at_bound = FROZEN_REPLICA_PEAK + FOLLOWING_TOLERANCE;
    assert_eq!(
        handle.status(&db, tier_at(at_bound)).await.unwrap().phase,
        SyncPhase::Synced,
        "a node within the tolerance was reported as still syncing"
    );
    assert_eq!(
        handle
            .status(&db, tier_at(at_bound + 1))
            .await
            .unwrap()
            .phase,
        SyncPhase::Syncing,
        "a node one block past the tolerance was still reported as settled"
    );
}

/// **Proves (dig_ecosystem#2851):** an unmeasured height on EITHER side leaves the phase exactly as
/// it was.
///
/// The Option-honesty guard. `None` is unobservable, never a zero, and an unobservable gap is not
/// an accusation — a node with no chain transport must not be reported as behind a chain it cannot
/// see.
#[tokio::test]
async fn an_unmeasured_height_leaves_the_phase_unchanged() {
    let db = WalletDb::open_in_memory().await.unwrap();
    db.set_initial_sync_complete(true).await.unwrap();

    let (handle, _rx) = SyncHandle::new();
    handle.set_connected(1);
    handle.set_trust(true);
    handle.set_watched(1, true);

    // The replica's own peak is unknown; the peers' is far ahead.
    assert_eq!(
        handle.status(&db, tier_at(PEERS_PEAK)).await.unwrap().phase,
        SyncPhase::Synced,
        "an unknown replica peak was read as evidence of being behind"
    );

    // The replica's peak is known; nobody has measured the peers'.
    db.set_peak(FROZEN_REPLICA_PEAK, "aa").await.unwrap();
    assert_eq!(
        handle
            .status(&db, ChainPeerTier::UNOBSERVABLE)
            .await
            .unwrap()
            .phase,
        SyncPhase::Synced,
        "an unobservable peer tier was read as evidence against the replica"
    );
}

/// **Proves:** the CORROBORATED read is what reaches spend-path coin selection — there is no
/// second, uncorroborated path underneath it.
///
/// Coin selection reads the replica, and [`routing::route`] is the gate that decides whether the
/// replica answers for money at all. That gate turns on `initial_sync_complete`, which
/// `initial_sync_with_authority` is the only peer-reachable writer of, and which is now reachable only
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
    let (db, _) = run_discovered_session(unanimous(HONEST_HASH), Some(LIARS_HASH)).await;
    assert_eq!(
        routing::route(db.is_synced().await.unwrap(), true),
        Source::Fallback,
        "an uncorroborated peer's replica was routed to for a wallet-scoped read"
    );

    // Corroborated: the same read now comes from the replica the quorum vouched for.
    let (db, _) = run_discovered_session(unanimous(HONEST_HASH), Some(HONEST_HASH)).await;
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
        verdict: unanimous(HONEST_HASH),
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

// ---------------------------------------------------------------------------
// The union source (dig_ecosystem#2823) — custody ∪ externally-registered keys
// ---------------------------------------------------------------------------

/// A distinct, valid G1 key per `tag`, standing in for a key dig-app registered.
fn registered_key(tag: u8) -> chia::bls::PublicKey {
    let mut seed = [0u8; 64];
    seed[0] = tag;
    chia::bls::SecretKey::from_seed(&seed).public_key()
}

/// **Proves (#2823):** the §908 install — an account in dig-app, NO seed on the node — reaches a
/// non-empty subscription set through a registration alone.
///
/// This is the whole blocker: `watched_addresses` was permanently 0 there, `initial_sync` refused
/// the empty set by design, and the replica's peak never advanced.
///
/// `any_wallet()` is asserted separately because the two facts are independent: a source that
/// derived enrolment from the address set would pass the first assertion and still be the
/// implementation #2609 exists to forbid.
#[test]
fn a_node_with_no_custody_follows_registered_keys() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    let custody = WalletCustody::mainnet(dir.clone());
    let registry = crate::sage::watchlist::WatchRegistry::new(&dir);
    assert!(
        PuzzleHashSource::puzzle_hashes(&custody).is_empty(),
        "the premise: the node custodies nothing"
    );
    registry.watch(&[registered_key(1)]);

    let union = UnionPuzzleHashSource::new(custody, registry);

    assert_eq!(
        union.puzzle_hashes(),
        vec![puzzle_hash_for(&registered_key(1))],
        "a registered key must be followed even with no custody at all"
    );
    assert!(
        union.any_wallet(),
        "a node asked to follow an account HAS a wallet enrolled — reporting the \
         no-wallet-enrolled all-clear here would deny the user's coins are being tracked"
    );
}

/// **Proves (#2823, the under-report defect class #2762):** the union follows BOTH sides.
///
/// Custody holds one key and the registry a DIFFERENT one, which is what makes this test able to
/// see the two nearest wrong implementations — returning only custody's set, or only the
/// registry's. A fixture where the two sides overlap would pass under both.
#[test]
fn the_union_follows_custody_and_registered_keys_together() {
    let dir = scratch();
    let custody = WalletCustody::mainnet(dir.clone());
    custody
        .create(&test_custody_password(), None)
        .expect("create a custodied wallet");
    let custodied: Vec<Bytes32> = PuzzleHashSource::puzzle_hashes(&custody);
    assert!(!custodied.is_empty(), "a created wallet has public keys");

    let registry = crate::sage::watchlist::WatchRegistry::new(&dir);
    registry.watch(&[registered_key(2)]);
    let registered = puzzle_hash_for(&registered_key(2));
    assert!(
        !custodied.contains(&registered),
        "the fixture must keep the two sides disjoint, or it cannot see a dropped side"
    );

    let union = UnionPuzzleHashSource::new(custody, registry);
    let watched = union.puzzle_hashes();

    for ph in &custodied {
        assert!(
            watched.contains(ph),
            "dropping custody's own addresses would under-report the NODE's balance"
        );
    }
    assert!(
        watched.contains(&registered),
        "dropping the registered address would under-report the USER's balance"
    );
    assert_eq!(watched.len(), custodied.len() + 1);
}

/// **Proves (#2823):** `unwatch` genuinely stops the following.
///
/// A second registered key stays enrolled as an honest control, so an implementation that clears
/// the whole registry — or that removes from the file while the live set keeps serving the
/// supervisor — is visible rather than passing.
#[test]
fn unwatch_removes_the_address_from_the_subscription_set() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    let registry = crate::sage::watchlist::WatchRegistry::new(&dir);
    registry.watch(&[registered_key(3), registered_key(4)]);
    let union = UnionPuzzleHashSource::new(WalletCustody::mainnet(dir.clone()), registry.clone());
    assert_eq!(union.puzzle_hashes().len(), 2);

    registry.unwatch(&[registered_key(3)]);

    assert_eq!(
        union.puzzle_hashes(),
        vec![puzzle_hash_for(&registered_key(4))],
        "the deregistered address must leave the set the supervisor re-reads, and only it"
    );
    let after_restart = UnionPuzzleHashSource::new(
        WalletCustody::mainnet(dir.clone()),
        crate::sage::watchlist::WatchRegistry::new(&dir),
    );
    assert_eq!(
        after_restart.puzzle_hashes(),
        vec![puzzle_hash_for(&registered_key(4))],
        "and a restart must not resurrect it"
    );
}

/// **Proves (#2823):** a key present on BOTH sides yields ONE puzzle hash.
///
/// dig-app registering an account the node also custodies is an ordinary state, and a duplicated
/// hash would be sent to the peer twice.
#[test]
fn a_key_held_by_both_sides_is_watched_once() {
    let dir = scratch();
    let custody = WalletCustody::mainnet(dir.clone());
    custody
        .create(&test_custody_password(), None)
        .expect("create a custodied wallet");
    let shared = *custody
        .custodied_public_keys()
        .iter()
        .next()
        .expect("a created wallet has public keys");

    let registry = crate::sage::watchlist::WatchRegistry::new(&dir);
    registry.watch(&[shared]);

    let watched = UnionPuzzleHashSource::new(custody.clone(), registry).puzzle_hashes();

    assert_eq!(
        watched,
        PuzzleHashSource::puzzle_hashes(&custody),
        "re-registering a custodied key must not change the set at all"
    );
}

/// **Proves (#2823 × #2609):** the two empty-set states stay distinguishable through the union.
///
/// With nothing custodied and nothing registered the node genuinely has no wallet, and that must
/// still read as the honest all-clear rather than as "enrolled but unwatched".
#[test]
fn an_empty_union_still_reports_the_honest_no_wallet_state() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    let union = UnionPuzzleHashSource::new(
        WalletCustody::mainnet(dir.clone()),
        crate::sage::watchlist::WatchRegistry::new(&dir),
    );

    assert!(union.puzzle_hashes().is_empty());
    assert!(
        !union.any_wallet(),
        "no custody and no registration is the genuine no-wallet install"
    );
}

/// **Proves (#2823 × #2609):** the union keeps the OTHER empty-set state honest too.
///
/// A node whose own wallet is enrolled but not unlocked derives no address and has registered
/// nothing, so the union's address set is empty while a wallet plainly exists. Computing enrolment
/// as `!puzzle_hashes().is_empty()` — the forbidden implementation, and the one nearest to hand
/// once two sources are being combined — passes every other test in this group and turns this red.
#[test]
fn an_enrolled_but_unreachable_custody_is_not_an_all_clear_through_the_union() {
    let dir = scratch();
    let custody = WalletCustody::mainnet(dir.clone());
    custody
        .create(&test_custody_password(), None)
        .expect("create a custodied wallet");
    // Drop the manifest so it is rebuilt from the seed file alone, without public keys — one of the
    // four reachable states where an enrolled wallet derives no address.
    std::fs::remove_file(dir.join("wallets").join("index.json")).expect("remove the manifest");
    let healed = WalletCustody::mainnet(dir.clone());

    let union =
        UnionPuzzleHashSource::new(healed, crate::sage::watchlist::WatchRegistry::new(&dir));

    assert!(
        union.puzzle_hashes().is_empty(),
        "the premise: no address is derivable and nothing is registered"
    );
    assert!(
        union.any_wallet(),
        "a wallet IS enrolled — its coins are simply not being followed, which must never read \
         as the no-wallet all-clear"
    );
}

// ---------------------------------------------------------------------------
// A catch-up is bounded and interruptible (dig_ecosystem#2851)
// ---------------------------------------------------------------------------

/// **Proves (dig_ecosystem#2851):** a catch-up that never returns is ABANDONED on a total deadline,
/// so the supervisor gets back to the reconnect path instead of holding one peer for ever.
///
/// The per-round-trip `PEER_REQUEST_TIMEOUT` bounds one answer, not the sequence of them. A peer
/// that answers each round trip just inside the bound satisfies it indefinitely, and the catch-up
/// runs OUTSIDE the supervisor's `select!` — so rotation, stall detection and shutdown are all
/// disarmed for the whole of it. At 60 seconds across up to 1024 batches that is about seventeen
/// hours in which nothing can end the session.
///
/// FIXTURE DESIGN — the double PARKS rather than erroring, because an erroring catch-up takes the
/// path that already worked and would pass against the defect. The deadline is the only timer this
/// test un-silences, so a reconnect can have come from nothing else; with the deadline removed the
/// supervisor stays on its first session and `until` fails LOUDLY on its own bound rather than
/// hanging.
#[tokio::test]
async fn a_catch_up_that_never_returns_is_abandoned_on_its_own_deadline() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    script.park_the_catch_up();
    script.allow(CATCH_UP_DEADLINE);

    let harness = Harness::start(
        db,
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])])),
        script.clone(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;

    harness
        .until(
            "the parked catch-up to be abandoned and a fresh peer dialled",
            |s| s.connects.load(Ordering::SeqCst) >= 2,
        )
        .await;

    assert!(
        script.catch_up_count() >= 2,
        "the supervisor reconnected without re-entering the catch-up, so the deadline is not what \
         ended the session"
    );

    harness.stop().await;
}

/// **Proves (dig_ecosystem#2851):** the node can be SHUT DOWN while a catch-up is running.
///
/// The half of the defect that is not about liveness at all. A catch-up sitting outside the
/// `select!` takes the shutdown signal with it, so `dig-node stop` — and every service manager that
/// wraps it — waits on a peer that has no reason to answer. A node that cannot be stopped for
/// seventeen hours is its own defect, whatever the sync eventually does.
///
/// FIXTURE DESIGN — the deadline stays SILENCED here, deliberately. It would otherwise end the
/// session on its own and the test would pass against a supervisor that still ignores shutdown
/// during a catch-up, which is the whole property. So the ONLY thing that can end this task is the
/// shutdown arm, and `Harness::stop`'s own five-second bound makes a regression fail loudly instead
/// of hanging the suite.
#[tokio::test]
async fn a_shutdown_is_honoured_while_a_catch_up_is_running() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    script.park_the_catch_up();

    let harness = Harness::start(
        db,
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])])),
        script.clone(),
        vec!["203.0.113.1:8444".into()],
    )
    .await;

    harness
        .until("the catch-up to be entered", |s| s.catch_up_count() >= 1)
        .await;

    // `stop` asserts the task actually ends; it is the assertion, not the teardown.
    harness.stop().await;
}

/// **Proves (dig_ecosystem#2851, A2 + F3):** the ceiling the ONE production construction site
/// builds is anchored on the QUORUM-settled height and scaled by the lifetime the supervisor was
/// actually given.
///
/// `trust_for_session` is the only place a `PeakCeiling` exists in production, and every other
/// ceiling test hand-constructs its authority — so the bound was pinned solely against itself.
/// Mutating the anchor to `round.height + 1_000_000`, or scaling by the `SESSION_MAX_LIFETIME`
/// constant instead of the injected lifetime, both left the whole suite green.
///
/// FIXTURE DESIGN — the injected lifetime is deliberately NOT the shipped constant. A test run at
/// `SESSION_MAX_LIFETIME` cannot tell the derived allowance from the hardcoded one, because the two
/// agree numerically at exactly that value; doubling it makes them disagree by 66 blocks. And the
/// anchor is asserted BOTH as an equality and as a refusal one million blocks up, because the
/// equality alone would still pass a ceiling that was merely wide.
#[tokio::test]
async fn the_ceiling_derives_from_the_quorum_height_and_the_injected_lifetime() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    *script.writer_answer.lock().unwrap() = Some(HONEST_HASH);
    // Twice the shipped value, so a ceiling scaled by the constant is a DIFFERENT number here.
    let lifetime = SESSION_MAX_LIFETIME * 2;

    let harness = Harness::start_with_lifetime(
        db,
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])])),
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
        Some(ScriptedCorroborator::new(unanimous(HONEST_HASH))),
        None,
        lifetime,
    )
    .await;
    harness
        .until("the corroborated session to catch up", |s| {
            s.catch_up_count() >= 1
        })
        .await;
    harness.stop().await;

    let authority = script.authorities.lock().unwrap()[0];
    let sync::WriteAuthority::Corroborated(ceiling) = authority else {
        panic!("a corroborated peer must be elevated WITH a ceiling, got {authority:?}");
    };
    assert_eq!(
        ceiling.anchor(),
        SETTLED_HEIGHT,
        "the ceiling must be anchored on the height the quorum settled, which the writer cannot          inflate — not on anything the writer said"
    );
    assert_eq!(
        ceiling.limit(),
        SETTLED_HEIGHT + sync::peak_allowance(lifetime),
        "the allowance must be derived from the lifetime this supervisor runs sessions for; a          hardcoded one silently becomes too tight when that value moves UP"
    );
    assert!(
        !ceiling.admits(SETTLED_HEIGHT + 1_000_000),
        "an anchor a million blocks above the settled height is not a bound at all"
    );
}

/// **Proves (dig_ecosystem#2851):** write authority is earned PER SESSION and is never inherited
/// from the session before it.
///
/// SPEC 18.6a states that a new session earns its authority from a freshly drawn quorum and that a
/// verdict MUST NOT be carried across sessions — and until this test, nothing pinned it. Every
/// rotation and stall test used a `PeerTrust::Operator` peer, which SHORT-CIRCUITS corroboration
/// before it runs, so hoisting the trust resolution out of the reconnect loop — the obvious
/// optimisation once someone reads the 144-corroborations-per-day cost this change documents —
/// left the entire suite green while handing every later session an authority it never earned.
///
/// FIXTURE DESIGN — exactly one thing varies, and it varies BETWEEN sessions rather than within
/// one. The peer is `Discovered`, so corroboration actually runs; the writer's answer never
/// changes, so the writer is not what differs; and the quorum corroborates the FIRST round and
/// splits on every later sample, which is precisely a verdict that must not be reusable. A double
/// that answered the same way for ever could not exhibit the difference at all.
///
/// The two assertions catch the hoist from opposite sides. A quorum drawn once shows up as a round
/// count that stops climbing while sessions keep turning over; an authority reused shows up as a
/// second catch-up, because a REFUSED session subscribes nothing and therefore never catches up.
#[tokio::test]
async fn a_session_earns_its_own_authority_and_never_inherits_one() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let script = Script::new();
    *script.writer_answer.lock().unwrap() = Some(HONEST_HASH);
    let corroborator = ScriptedCorroborator::corroborating_once_then_splitting(HONEST_HASH);

    let harness = Harness::start_with_lifetime(
        db,
        Arc::new(FixedHashes::unlocked(vec![Bytes32::new([7; 32])])),
        script.clone(),
        vec!["203.0.113.1:8444".into()],
        PeerTrust::Discovered,
        Some(corroborator.clone()),
        None,
        SESSION_MAX_LIFETIME,
    )
    .await;

    // Sessions turn over on their own here — the first on rotation, the refused ones on the
    // re-corroboration timer — and WHICH one ends a session is immaterial to the property, which is
    // only that each successor must ask again.
    harness
        .until("the session to be replaced by a successor", |s| {
            s.connects.load(Ordering::SeqCst) >= 3
        })
        .await;
    harness.stop().await;

    let sessions = script.connects.load(Ordering::SeqCst);
    assert!(
        corroborator.rounds() >= sessions,
        "corroboration ran {} times across {sessions} sessions, so a quorum was drawn once and \
         reused rather than redrawn per session",
        corroborator.rounds()
    );
    assert_eq!(
        script.catch_up_count(),
        1,
        "a session after the first caught up, so it wrote the replica on an authority the quorum \
         refused it — a verdict was carried across the session boundary"
    );
}
