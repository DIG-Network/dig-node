//! The background chain-sync supervisor (SPEC §18.6, dig_ecosystem#2501/#2408).
//!
//! [`crate::sage::sync`] is a complete subscription loop that, until now, had **no production
//! call site**: nothing connected a peer, nothing subscribed, and so `sync_state.peak_height`
//! stayed NULL on installs with only operator-chosen peers. This module is that missing call site
//! — it owns the peer lifecycle (connect, catch up, consume pushes, reconnect with backoff, shut
//! down) and exposes the small amount of live state the DB alone cannot express.
//!
//! On a DEFAULT install (no `user_managed` peer rows) the node dials a DISCOVERED peer. Such a
//! peer arrives untrusted and writes nothing — but it is no longer stuck there. Before any write,
//! the supervisor puts a settled-height question to an independently drawn quorum of other
//! randomly dialled peers ([`Corroborator`], [`crate::sage::quorum`]) and elevates the session to
//! [`PeerTrust::Corroborated`] only if the writer agrees with them. A default install therefore
//! reaches `initial_sync_complete` and an advancing `peak_height` without the operator naming a
//! single peer, which is what dig-node being a LIGHT CLIENT requires (dig_ecosystem#2568).
//!
//! When corroboration is unavailable, splits, or catches the writer out, the session stays
//! [`PeerTrust::Discovered`] and its whole contribution is liveness: `chia_peer_count` stays
//! non-null so the phase advances from `not_started` to `syncing`, and nothing is written. Such a
//! session is HELD FOR [`RECORROBORATE_AFTER`] AND THEN ENDED, so the ordinary reconnect path draws
//! an independent sample and asks again — corroboration runs once per session, so a refused session
//! that is never ended is a refusal that never expires (dig_ecosystem#2827).
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
//! [`crate::sage::sync::initial_sync_with_authority`] itself, which refuses with
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

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use chia::bls::PublicKey;
use chia::puzzles::standard::StandardArgs;
use chia_protocol::Bytes32;

use super::custody::WalletCustody;
use super::db::WalletDb;
use super::events::EventBus;
use super::quorum::{self, Verdict};
use super::sync::{self, PeerTrust, SyncError};
use super::watchlist::WatchRegistry;

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
/// How often a nothing-subscribed session re-reads the subscription set.
///
/// The default install has ZERO puzzle hashes, so the nothing-subscribed session is the common
/// path, and a subscription is per-connection state: the set is fixed for the life of a
/// connection. Without this poll a wallet created after boot waits for the peer to drop — which
/// can be hours — before anything subscribes it. Five seconds is imperceptible to the user
/// creating the wallet and is a local read of already-loaded public keys, so it costs nothing on
/// the wire.
const PUZZLE_HASH_POLL: Duration = Duration::from_secs(5);
/// How long a REFUSED session is held before it is ended so a fresh corroboration sample is drawn
/// (dig_ecosystem#2827).
///
/// Corroboration runs once, at session start. Without this, a single non-elevating round parked the
/// node on a peer it could never write from for the LIFE OF THE PROCESS: the refused session
/// subscribes nothing, so the resubscribe poll is disarmed too, and the only remaining exit was the
/// peer disconnecting — which a healthy peer never does. A user's replica sat at height 9,139,211
/// for hours, five peers held, while the chain moved on and their wallet reported no balance.
///
/// FORTY-FIVE SECONDS BALANCES THE TWO FAILURES EITHER SIDE OF IT. Shorter, and a genuinely
/// partitioned network is re-dialled in a near-tight loop across the same four DNS introducers that
/// [`BACKOFF_MAX`] exists to protect. Longer, and a transient shortfall — one slow round, a
/// momentarily thin peer set — costs the user minutes of a visibly frozen balance for no reason.
/// It sits just below [`BACKOFF_MAX`], so a persistently refusing network converges on the backoff
/// ladder's own ceiling rather than out-pacing it, and it is short enough that the cost of a
/// transient refusal is under a minute instead of unbounded.
const RECORROBORATE_AFTER: Duration = Duration::from_secs(45);
/// How often a stalled-session check re-measures the replica against the chain.
///
/// Two local reads — one DB row and the chain transport's last-heard peak — so the poll costs
/// nothing on the wire and cannot itself keep a peer busy. Fifteen seconds is just under a mainnet
/// block interval (~19s), so a healthy replica advances within a poll or two and the stall clock is
/// reset by evidence rather than by luck.
const STALL_POLL: Duration = Duration::from_secs(15);
/// The TOTAL time one catch-up may take before the session is abandoned (dig_ecosystem#2851).
///
/// `sync::PEER_REQUEST_TIMEOUT` bounds ONE round trip, and deliberately so: a catch-up runs from
/// genesis over many batches, and a total deadline tight enough to be interesting would abort a
/// healthy long sync and restart it from the beginning for ever. But a per-round-trip bound is not
/// a bound on the SEQUENCE — a peer answering each round trip just inside 60 seconds satisfies it
/// indefinitely, which across the batch limit is about seventeen hours with rotation, stall
/// detection and shutdown all disarmed, because the catch-up runs outside the supervisor's
/// `select!`.
///
/// # Why ONE deadline, and not a shorter one for a re-catch-up
///
/// A first catch-up on a fresh install and a re-catch-up on a warm DB were both candidates for
/// separate budgets, and separating them was considered and rejected: EVERY catch-up here runs from
/// genesis. A reconnecting peer has no memory of the previous subscription and resuming from the
/// stored `(height, header_hash)` is not safe, so "first" and "subsequent" describe the same work.
/// What differs is how much coin state comes back, which is a property of the WALLET's history and
/// not of whether this process has synced before — so a discriminator would have split the budget
/// along an axis that does not predict the cost. (`initial_sync_complete` would have been the wrong
/// one twice over: it is cleared on any accepted reorg, so an untrusted peer can choose which
/// budget applies.)
///
/// AN HOUR IS DELIBERATELY GENEROUS, and the asymmetry is why. Both catch-ups measured on the live
/// host completed in 54-81 MILLISECONDS, so this is four orders of magnitude above anything
/// observed, while still being a twentieth of the unbounded worst case. Too tight is the far worse
/// error: an aborted catch-up restarts from genesis, so a deadline a legitimate sync cannot meet
/// produces a replica that never finishes — the failure this whole ticket is about. Too loose
/// merely leaves a pathological peer holding a session it cannot usefully do anything with, and
/// SHUTDOWN is no longer among the things it holds.
const CATCH_UP_DEADLINE: Duration = Duration::from_secs(3_600);
/// How long a session may hold the replica STILL, while the chain demonstrably advances, before it
/// is ended (dig_ecosystem#2851).
///
/// # The three session timescales, and why none of them collapses into another
///
/// THE ONE PLACE THE LADDER IS STATED, so it cannot be half-updated:
///
/// [`RECORROBORATE_AFTER`] (45s) < `STALL_AFTER` (90s) < [`SESSION_MAX_LIFETIME`] (600s)
///
/// Each governs a DIFFERENT concern, and the ORDERING IS DELIBERATE: a session that CANNOT write is
/// dropped soonest, one that has STOPPED writing next, and a perfectly healthy one is held longest,
/// until the anti-capture bound. Collapsing any two of them would silently retire one of the three
/// concerns — and the widest gap, between this deadline and rotation, is the load-bearing one:
/// rotation is nearly seven times slower, so it can neither substitute for this detector nor be
/// relied on to end a freeze in time.
///
/// The ladder is restated normatively in SPEC §18.6a and nowhere else in this crate.
///
/// A half-open peer connection parks [`crate::sage::sync::run_update_loop`] on a `recv()` that has
/// no deadline. For an AUTHORITATIVE subscribed session that was the last exit: the resubscribe
/// poll is armed only while nothing is subscribed, [`RECORROBORATE_AFTER`] is armed only for a
/// refused session, and the peer never disconnects. A user's replica froze at height 9,142,861
/// while their peers announced 9,142,918 and the gap grew without bound — reported, throughout, as
/// `synced`.
///
/// THIS IS THE ONLY FAST PATH, so it is biased FAST, and the bias is justified by what being wrong
/// costs in each direction. A needless reconnect costs a catch-up — measured at 54 MILLISECONDS on
/// the live host (corroboration logged at 08:34:21.495, the update loop already handling frames at
/// 08:34:21.549), because `request_puzzle_state` is indexed by puzzle hash rather than walking
/// blocks — plus ONE corroboration round of up to `quorum::QUORUM_DIAL_WIDE` dials. Being wrong the
/// other way costs a user staring at a stale balance while their node calls it settled. Ninety
/// seconds is about FIVE consecutive missed peaks *while the peers' peak demonstrably advanced*,
/// which no healthy session produces.
///
/// It exceeds [`HEALTHY_SESSION`], so a session ended this way still counts as healthy at
/// [`Supervisor::run`]'s ladder reset and reconnects promptly instead of climbing the backoff
/// ladder toward [`BACKOFF_MAX`].
pub(crate) const STALL_AFTER: Duration = Duration::from_secs(90);
/// How long ONE subscription session runs before it is retired and a fresh peer is dialled.
///
/// AN ANTI-CAPTURE BOUND, NOT A LIVENESS MECHANISM. Liveness belongs to [`STALL_AFTER`], which
/// compares two numbers that are already on one status payload; this exists only so that a hostile
/// or merely unlucky peer set cannot be HELD indefinitely. Once the detector exists, nothing about
/// rotation needs to be quick — the connection is HELD, not churned.
///
/// TEN MINUTES IS AN OPERATING ASSUMPTION, overridable, not a derived constant. What it trades:
///
/// * The CATCH-UP is not the cost — 54 ms, measured above.
/// * CORROBORATION is. `quorum::QUORUM_DIAL_WIDE` peers are dialled once per session, so the
///   cadence is a sustained dial rate for the life of the process. [`BACKOFF_MAX`]'s own doc
///   records that four DNS introducers serve the whole network and that a tight loop across many
///   nodes is the failure it exists to bound. One node is nothing; the aggregate is the risk, which
///   is why this number moves UP rather than down.
///
/// The corroboration bar MUST NOT be weakened to pay for it: every new session is a NEW peer and
/// re-earns its write authority from a freshly drawn quorum. Carrying a verdict across sessions
/// would hand the replica to an uncorroborated writer, which is the vulnerability the mechanism
/// exists to close (NC-12).
///
/// Nothing is staggered here, because this is a set of ONE session. Staggering is load-bearing only
/// for `chia-query`'s peer POOL (dig_ecosystem#2791/#2836), where a simultaneous turnover would
/// empty the corroboration pool exactly when a round needs it. That is a different repo and is
/// deliberately not solved here.
pub const SESSION_MAX_LIFETIME: Duration = Duration::from_secs(600);
/// How far the replica may trail the node's own peers and still be called
/// [`SyncPhase::Synced`] — about 75 seconds of chain at a ~19s block interval.
///
/// THE TWO FAILURE DIRECTIONS ARE NOT SYMMETRIC, which is what fixes the number. Too tight and a
/// healthy node reports `syncing` for a block or two around every peak — conservative, visible, and
/// harmless. Too loose and the node keeps telling a client that a stale balance is SETTLED, which
/// is the money-adjacent falsehood dig_ecosystem#2851 exists to remove. Four blocks absorbs the
/// ordinary skew between hearing a peak and writing it without absorbing a freeze.
///
/// It is deliberately NOT [`STALL_AFTER`]'s threshold. The two answer different questions at
/// different costs: this one asks *what may I claim about the number I am serving right now*, and
/// is free to be strict because being wrong only understates confidence; that one asks *should I
/// pay for a catch-up from genesis*, and must be slack because being wrong burns real work.
const FOLLOWING_TOLERANCE: u32 = 4;

// ---------------------------------------------------------------------------
// The observable state
// ---------------------------------------------------------------------------

/// Declares the sync phases ONCE, and derives everything from that single list.
///
/// The enum, [`SyncPhase::ALL`] and [`SyncPhase::as_wire`] are all expanded from the same
/// invocation, so a variant CANNOT exist without appearing in `ALL` and without a wire spelling.
/// That is the whole reason this is a macro rather than three hand-maintained lists.
///
/// # The hole this closes, which was found by execution
///
/// `ALL` used to be a hand-written slice with no compile-time tie to the enum. Both pre-merge
/// gates independently built the same probe: add a variant, give it an `as_wire` arm (the compiler
/// demands one), leave `ALL` alone — and every conformance check passed, because all three of them
/// iterate `ALL` and therefore could not see the variant missing from it. The node would ship a
/// token the published contract had never heard of: dig_ecosystem#2609, recurring through the very
/// guard written to prevent it.
///
/// A gate that cannot observe the thing it claims to observe is a decoration. Deriving the list
/// makes the omission unrepresentable rather than merely discouraged.
macro_rules! declare_sync_phases {
    ($( $(#[$variant_doc:meta])* $variant:ident => $wire:literal ),+ $(,)?) => {
        /// The wallet's sync phase, as a consumer should render it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum SyncPhase {
            $( $(#[$variant_doc])* $variant, )+
        }

        impl SyncPhase {
            /// Every phase this node can emit, derived from the declaration above.
            ///
            /// The published `dig_node_control_interface::results::WalletSyncPhase` carries the
            /// same set, and this list MUST be a SUBSET of it — the contract states that a node
            /// must not emit a token outside its declared set. `dig-wallet` cannot see that crate,
            /// so the two are tied together by a conformance test in `dig-node-service`, which
            /// can see both.
            pub const ALL: &'static [SyncPhase] = &[ $( SyncPhase::$variant ),+ ];

            /// This phase's exact wire spelling.
            ///
            /// Pinned against the serde output by a test in this module, so a `rename_all` change
            /// cannot leave this describing a spelling the wire no longer uses.
            pub fn as_wire(self) -> &'static str {
                match self { $( SyncPhase::$variant => $wire ),+ }
            }
        }
    };
}

declare_sync_phases! {
    /// No peer has ever been attached in this process. Nothing is known yet.
    NotStarted => "not_started",
    /// A peer is attaching, catching up, or the replica is otherwise not both caught up AND
    /// currently following the chain.
    Syncing => "syncing",
    /// A catch-up has completed, a peer is attached right now, AND addresses are actually being
    /// watched.
    ///
    /// The last clause is not decoration. `initial_sync_complete` is persistent, so on its own it
    /// would report a wallet that caught up yesterday and restarted LOCKED as settled while
    /// watching nothing — see the arm ordering in [`SyncHandle::status`].
    Synced => "synced",
    /// **The honest all-clear: NO wallet is enrolled**, so there are no addresses to follow and a
    /// sync has nothing to do.
    ///
    /// This is the DEFAULT-INSTALL state, not an edge (dig_ecosystem#2609). With zero puzzle
    /// hashes [`crate::sage::sync::initial_sync_with_authority`] refuses to run, so `initial_sync_complete` never
    /// latches — while `new_peak_wallet` keeps the replica's peak advancing with the chain.
    /// Reported as `Syncing`, that made every consumer say "your node is still catching up" for
    /// ever about a node sitting at the tip.
    ///
    /// It is NOT a fourth way of spelling `Synced`: `Synced` licenses
    /// [`crate::sage::routing::route`] to serve wallet-scoped reads from the local replica, and
    /// over an un-queried DB that reads a funded wallet as empty. This says the chain replica is
    /// current AND that no wallet-scoped claim is being made at all.
    NoWalletEnrolled => "no_wallet_enrolled",
    /// **A wallet IS enrolled, but no addresses are being watched for it** — so the user's coins
    /// are not being followed.
    ///
    /// Distinguished from [`Self::NoWalletEnrolled`] because the two are identical from inside the
    /// sync loop and mean opposite things: *nothing to do* versus *something to do that is not
    /// being done*. Collapsing them would report a wallet whose coins are unwatched as an
    /// all-clear — the exact class of falsehood #2609 exists to remove, one conflation further
    /// along.
    ///
    /// This is the COMMON state after every restart. [`super::custody::WalletCustody`] derives the
    /// address set from key material it cannot reach while the wallet is locked, and nothing
    /// back-fills it; an adopted legacy seed, a manifest predating the stored-public-keys field, a
    /// self-healed manifest, and an entry whose key fails to decode all reach it too.
    ///
    /// Named NOT UNLOCKED rather than *locked* deliberately: an empty address set is what the node
    /// can OBSERVE, and a lock is only the usual cause. A manifest that never carried the keys
    /// arrives here with nothing locked. The phase claims the observation, not the cause.
    WalletNotUnlocked => "wallet_not_unlocked",
}

/// The composed sync status: the phase, the replica's own peak, and the live peer count.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WalletSyncStatus {
    /// The phase a consumer renders.
    pub phase: SyncPhase,
    /// The REPLICA's own peak height. `None` means unknown — never 0-for-unknown, because a
    /// consumer cannot tell a genuine height 0 from "we have not looked".
    pub peak_height: Option<u32>,
    /// Chia full nodes this node HOLDS — the peers that serve its chain reads
    /// (dig_ecosystem#2806).
    ///
    /// This is the node's headline "am I a light client" number, and it is the LIVE count of the
    /// chain transport's peer pool: a pool still filling reports the smaller number and reports
    /// its target only on reaching it. `None` is unobservable (no transport, or none could be
    /// built), never an observed zero.
    ///
    /// It is deliberately NOT [`Self::subscription_peer_count`] and MUST NOT be summed with it.
    /// Until dig_ecosystem#2806 this field carried that number instead, which is why a node with
    /// five peers serving every read reported `chia_peer_count: 1`: it was quoting the
    /// supervisor's single subscription session, which is neither the peers serving reads nor the
    /// total. The two are separate sets with separate lifetimes, so adding them would produce a
    /// larger number that describes nothing.
    pub chia_peer_count: Option<u32>,
    /// The REPLICA's subscription peers — what [`Self::chia_peer_count`] used to report.
    ///
    /// `Some(0)` is an OBSERVED zero (a supervisor is running and holds no peer); `None` is
    /// unobservable (no supervisor attached at all). The supervisor holds AT MOST ONE by design
    /// (see [`SyncSession`]), so this is a 0-or-1 fact about whether the replica is being written,
    /// never a measure of network reach — and reading it as one is exactly the confusion that
    /// made the node look like a one-peer client.
    pub subscription_peer_count: Option<u32>,
    /// The peak height the node's OWN Chia peers announced (dig_ecosystem#2806).
    ///
    /// Distinct from [`Self::peak_height`], which is the replica's own progress, and from any
    /// oracle reading: this is what the node's peers told it directly, so a value here is
    /// evidence those peers are live and talking. `None` until one of them says something —
    /// never zero, which every block is trivially above.
    pub chia_peer_peak_height: Option<u32>,
    /// How many custodied puzzle hashes the ATTACHED session resolved for subscription.
    ///
    /// `Some(0)` is a MEASURED zero — custody genuinely holds nothing, which is the reason behind
    /// [`SyncPhase::NoWalletEnrolled`]. `None` is unmeasured: no session is attached, or one is
    /// attached but has not yet resolved its set (corroboration runs first, and takes real time).
    /// The two must stay distinguishable — a `0` that merely means "not looked yet" would announce
    /// "nothing to watch" during every connect.
    ///
    /// It is reported so a consumer can state the REASON for the phase rather than infer it from
    /// the phase word (dig_ecosystem#2609).
    pub watched_addresses: Option<u32>,
}

/// Live counters the supervisor writes and the control layer only reads.
#[derive(Debug, Default, Clone, Copy)]
struct Observed {
    /// Whether a peer has ever been attached in this process.
    ever_connected: bool,
    /// Subscription peers held right now — 0 or 1 (see [`SyncSession`] on why one).
    peers: u32,
    /// Whether the ATTACHED session may write, i.e. the effective trust the supervisor resolved
    /// for it is [`PeerTrust::Operator`] or [`PeerTrust::Corroborated`].
    ///
    /// Recorded separately from the subscription count because the supervisor FORCES the
    /// subscription set empty for an uncorroborated peer. Without this flag, "subscribed nothing"
    /// cannot be told apart from "custody holds nothing", and a refused writer — a replica
    /// deliberately not being written — would report as the benign nothing-to-watch state.
    session_may_write: bool,
    /// How many puzzle hashes the ATTACHED session resolved. `None` until a session resolves its
    /// set; see [`WalletSyncStatus::watched_addresses`] on why measured-zero must not be spelled
    /// the same way as unmeasured.
    watched: Option<u32>,
    /// Whether a wallet was enrolled when the attached session resolved its set — read from the
    /// manifest, not from the derivable keys, so a LOCKED wallet still counts as enrolled.
    /// Measured in the same breath as [`Self::watched`], because the pair is only meaningful
    /// together.
    wallet_enrolled: bool,
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
    /// `Synced` requires a completed catch-up, a peer attached now, AND the replica actually
    /// following the chain ([`is_following`]): an offline replica is stale, however complete its
    /// last catch-up was, and reporting it synced is the shape that makes a client trust a day-old
    /// balance. Neither of the first two clauses is about the PRESENT — one is a latched flag, the
    /// other says a socket exists — so a replica frozen behind a half-open peer satisfied both and
    /// reported `synced` for as long as the process lived (dig_ecosystem#2851).
    ///
    /// `tier` is the node's own Chia peer tier, measured by the caller (which holds the chain
    /// transport; the supervisor does not). It is passed IN rather than defaulted so the status
    /// is built complete in one place — a field left to be patched afterwards is a field that
    /// ships as `None` the first time a new call site forgets it.
    pub async fn status(
        &self,
        db: &WalletDb,
        tier: super::fallback::ChainPeerTier,
    ) -> sqlx::Result<WalletSyncStatus> {
        let observed = self.observed();
        let state = db.sync_state().await?;
        let phase = if !observed.ever_connected {
            SyncPhase::NotStarted
        } else if observed.peers >= 1 && observed.session_may_write && observed.watched == Some(0) {
            // Three facts get us to "this session is watching nothing", and each rules out a
            // different lie:
            //   * a peer attached RIGHT NOW      — an offline replica is stale, not current;
            //   * that peer MAY WRITE            — a refused writer subscribes nothing too, and
            //                                      its replica is falling behind, not idle;
            //   * a MEASURED zero watched set    — `None` means the set is not resolved yet, and
            //                                      claiming anything then would be an unmeasured
            //                                      default announcing itself as a fact.
            //
            // THE ORDER OF THESE ARMS IS LOAD-BEARING: this one MUST precede `Synced`.
            // `initial_sync_complete` is persistent — it records that a catch-up once finished, and
            // only a backwards chain move clears it. So a wallet that was unlocked, caught up, and
            // then RESTARTED (locked) still carries the latched flag while watching zero addresses.
            // With `Synced` tested first, that node reported `synced` alongside
            // `watched_addresses: 0` — settled, while the user's coins were not being followed —
            // on the single most common post-restart path. Checking the empty set first means a
            // completed catch-up can never speak for a session that is watching nothing AND whose
            // peer may write.
            //
            // THAT QUALIFIER IS LOAD-BEARING, NOT PEDANTRY. A REFUSED writer skips this arm
            // entirely, because `session_may_write` is false, and falls through to `Synced` with a
            // MEASURED zero watched set — `{phase: synced, watched_addresses: 0}`, the exact pair
            // this arm exists to abolish, reached through the `PeerTrust::Discovered` door. This
            // commit SHRINKS the set of states that can tell that lie; it does not empty it.
            // The residue is #2666 and is not closed here.
            //
            // A FOURTH fact then decides WHICH nothing-to-watch this is, and the two mean opposite
            // things: no wallet at all is the honest all-clear, whereas an enrolled wallet whose
            // addresses are unreachable has coins that are NOT being followed. They are
            // indistinguishable from the address set alone, which is exactly how the first version
            // of this fix came to report a locked wallet as settled.
            if observed.wallet_enrolled {
                SyncPhase::WalletNotUnlocked
            } else {
                SyncPhase::NoWalletEnrolled
            }
        } else if state.initial_sync_complete
            && observed.peers >= 1
            && is_following(state.peak_height, tier.peak_height)
        {
            SyncPhase::Synced
        } else {
            SyncPhase::Syncing
        };
        Ok(WalletSyncStatus {
            phase,
            peak_height: state.peak_height,
            chia_peer_count: tier.peer_count,
            subscription_peer_count: Some(observed.peers),
            chia_peer_peak_height: tier.peak_height,
            watched_addresses: observed.watched,
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

    /// A handle attached to NO supervisor, reporting `peers` peers — so a test can give the
    /// Chia peer count a distinctive, non-default value without dialling the network.
    ///
    /// It exists because the "both methods report ONE observation" conformance property is
    /// otherwise inexpressible: with no supervisor running, both methods answer `null`, and a
    /// test comparing two `null`s compares two unobservables and passes against a handler that
    /// returns a literal. Dropping this handle stops nothing, because it started nothing.
    #[doc(hidden)]
    pub fn detached_for_tests(peers: u32) -> Self {
        let (handle, _rx) = Self::new();
        handle.set_connected(peers);
        handle
    }

    fn set_connected(&self, peers: u32) {
        let mut o = self.inner.observed.write().expect("observed lock poisoned");
        if peers > 0 {
            o.ever_connected = true;
        }
        o.peers = peers;
        if peers == 0 {
            // A dropped session's measurement is no longer a measurement. Leaving it behind would
            // let a peerless node keep answering as though a session had just resolved its set.
            o.session_may_write = false;
            o.watched = None;
            o.wallet_enrolled = false;
        }
    }

    /// Record the trust the supervisor resolved for the attached session — whether it may write.
    ///
    /// Written SEPARATELY from, and BEFORE, [`Self::set_watched`], because that is the order the
    /// supervisor actually learns the two facts: `trust_for_session` settles the trust (a
    /// corroboration round that dials several peers), and only then is a subscription set
    /// resolved for it. Writing both at once would make the in-between state — trust known, set
    /// not yet resolved — unreachable, and an unreachable state cannot be tested, which is
    /// exactly how a defensive condition rots into a decoration.
    #[doc(hidden)]
    pub fn set_trust(&self, may_write: bool) {
        let mut o = self.inner.observed.write().expect("observed lock poisoned");
        o.session_may_write = may_write;
    }

    /// Record how many custodied puzzle hashes the attached session resolved for subscription.
    ///
    /// This is the MEASUREMENT that turns `watched` from `None` into `Some(n)`; until it lands,
    /// the count is genuinely unknown even though the trust may already be decided.
    ///
    /// `wallet_enrolled` is taken in the SAME call because an empty count is only interpretable
    /// beside it: zero-with-no-wallet and zero-with-a-locked-wallet are the same number and
    /// opposite states.
    #[doc(hidden)]
    pub fn set_watched(&self, watched: u32, wallet_enrolled: bool) {
        let mut o = self.inner.observed.write().expect("observed lock poisoned");
        o.watched = Some(watched);
        o.wallet_enrolled = wallet_enrolled;
    }
}

/// Whether the replica is following the chain RIGHT NOW, judged by the only evidence the status
/// payload already carries: the gap between the replica's own peak and what the node's OWN peers
/// announced.
///
/// `None` on either side is UNOBSERVABLE, and an unobservable gap is never an accusation — it
/// answers `true` and leaves the phase exactly as it was before this existed. That matters because
/// the peer tier is genuinely unmeasured on a node whose chain transport has not been built, and a
/// missing measurement must not be spent as evidence against the replica.
///
/// See [`FOLLOWING_TOLERANCE`] for why the slack is small and which way it is allowed to be wrong.
pub(crate) fn is_following(replica: Option<u32>, peers: Option<u32>) -> bool {
    match (replica, peers) {
        (Some(replica), Some(peers)) => peers.saturating_sub(replica) <= FOLLOWING_TOLERANCE,
        _ => true,
    }
}

/// The status to report when NO supervisor is attached: the DB's peak is still honest, and the
/// SUBSCRIPTION peer count is unobservable rather than zero.
///
/// The chain-transport tier is still reported, because it is a different thing entirely: a node
/// with chain sync switched off can still hold peers and serve reads from them, and saying
/// otherwise would understate what the node is.
pub async fn status_without_supervisor(
    db: &WalletDb,
    tier: super::fallback::ChainPeerTier,
) -> sqlx::Result<WalletSyncStatus> {
    let state = db.sync_state().await?;
    Ok(WalletSyncStatus {
        phase: SyncPhase::NotStarted,
        peak_height: state.peak_height,
        chia_peer_count: tier.peer_count,
        // No supervisor is attached, so nobody is holding a subscription session to count.
        subscription_peer_count: None,
        chia_peer_peak_height: tier.peak_height,
        // Nothing is attached, so nothing has resolved a subscription set to report.
        watched_addresses: None,
    })
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// Where the supervisor's subscription set comes from.
///
/// Re-read on every connect attempt, and — while a session is running with NOTHING subscribed —
/// re-polled every [`PUZZLE_HASH_POLL`], so a wallet created after boot is picked up within
/// seconds without restarting the node and without waiting for the peer to drop.
pub trait PuzzleHashSource: Send + Sync {
    /// The puzzle hashes to subscribe. Empty is a legitimate answer (no wallet yet).
    fn puzzle_hashes(&self) -> Vec<Bytes32>;

    /// Whether ANY wallet is enrolled on this node, regardless of whether its addresses are
    /// currently derivable.
    ///
    /// The fact that separates the two empty-set states (dig_ecosystem#2609). An empty
    /// [`Self::puzzle_hashes`] is produced BOTH by a node that has no wallet — the honest
    /// all-clear — and by an enrolled wallet whose keys the node cannot reach, which is the common
    /// state after every restart and means the user's coins are NOT being followed. The two are
    /// indistinguishable from the address set alone, so the phase has to ask this separately.
    fn any_wallet(&self) -> bool;
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

    /// Reads the manifest, NOT the derivable key set — which is the entire point. A locked wallet
    /// is enrolled and contributes no puzzle hashes, and only this distinguishes it from a node
    /// that has no wallet at all.
    fn any_wallet(&self) -> bool {
        WalletCustody::any_wallet(self)
    }
}

/// Custody's own addresses PLUS the ones an external client registered
/// ([`super::watchlist::WatchRegistry`], dig_ecosystem#2823).
///
/// # Why the union, and not a replacement
///
/// The two sets answer different questions and both must be followed. Custody's set is the coins
/// the NODE holds; the registry's set is the coins the node was ASKED to follow for a user whose
/// account lives in dig-app (§908 — the node holds no seed on that install, so custody contributes
/// nothing at all). Serving either alone silently follows fewer addresses than the operator
/// arranged, and a too-narrow watch set under-reports a BALANCE — a wrong number that looks like a
/// working feature (dig_ecosystem#2762). The union is the only answer that cannot do that.
///
/// Both sides map through the SAME `StandardArgs::curry_tree_hash` derivation
/// ([`puzzle_hash_for`]), so there is exactly one public-key → puzzle-hash mapping in the
/// ecosystem and no app/node byte-drift (§4.1). A key present on both sides yields ONE hash.
pub struct UnionPuzzleHashSource {
    /// The node's own custody.
    custody: WalletCustody,
    /// Keys registered over `control.wallet.watch`.
    registry: WatchRegistry,
}

impl UnionPuzzleHashSource {
    /// Compose the node's custody with its watch registry.
    pub fn new(custody: WalletCustody, registry: WatchRegistry) -> Self {
        Self { custody, registry }
    }
}

impl PuzzleHashSource for UnionPuzzleHashSource {
    fn puzzle_hashes(&self) -> Vec<Bytes32> {
        let mut hashes: BTreeSet<Bytes32> = PuzzleHashSource::puzzle_hashes(&self.custody)
            .into_iter()
            .collect();
        hashes.extend(self.registry.registered().iter().map(puzzle_hash_for));
        // Sorted + deduplicated by construction, so a subscription (and a test asserting one) is
        // reproducible regardless of which side contributed a hash.
        hashes.into_iter().collect()
    }

    /// A node with registered keys and NO custody genuinely has a wallet enrolled, so it must not
    /// report the `NoWalletEnrolled` all-clear — that is the §908 install, and on it the registry
    /// is the only evidence a wallet exists at all.
    ///
    /// Asked separately from [`Self::puzzle_hashes`] for the reason the trait documents: an empty
    /// address set means *nothing to do* or *something to do that is not being done*, and only this
    /// distinguishes them (dig_ecosystem#2609).
    fn any_wallet(&self) -> bool {
        PuzzleHashSource::any_wallet(&self.custody) || !self.registry.is_empty()
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

    /// The trust this peer carries INTO the session, decided by HOW it was reached and by
    /// nothing it says ([`trust_for`]).
    ///
    /// It is a starting point, not a verdict. A [`PeerTrust::Discovered`] peer may be elevated
    /// to [`PeerTrust::Corroborated`] before any write, by the [`Corroborator`], and only then.
    fn trust(&self) -> PeerTrust;

    /// This peer's answer to "what is the canonical header hash at `height`?".
    ///
    /// The question a would-be writer must answer correctly to be elevated. Note what the session
    /// does NOT get to do: it never chooses `height`. That is settled entirely by the
    /// independently drawn quorum ([`Corroborator::corroborate`]), because a writer that could
    /// pick its own exam height could pick one it had prepared an answer for.
    ///
    /// `Ok(None)` means the peer declined or does not have the block — indistinguishable from a
    /// wrong answer for elevation purposes, and treated the same way: no elevation.
    async fn header_hash_at(&self, height: u32) -> Result<Option<Bytes32>, SyncError>;

    /// Subscribe `puzzle_hashes` and catch the replica up, under the EFFECTIVE trust the
    /// supervisor resolved for this session.
    ///
    /// `authority` is passed in rather than read from [`SyncSession::trust`] because the two can
    /// legitimately differ: a discovered peer that cleared corroboration runs as
    /// [`PeerTrust::Corroborated`] while its dial source is still discovery. The floor check that
    /// actually guards `initial_sync_complete` lives down in
    /// [`sync::initial_sync_with_authority`] — where the previous audit deliberately put it, so no
    /// caller-side refactor can walk around it — and it can only see what it is handed.
    ///
    /// It carries the session's [`sync::PeakCeiling`] as well as its trust, because the catch-up
    /// TERMINAL is a peak claim like any other and is checked against the same bound
    /// (dig_ecosystem#2851).
    async fn catch_up(
        &self,
        db: &WalletDb,
        puzzle_hashes: Vec<Bytes32>,
        genesis_challenge: Bytes32,
        events: &EventBus,
        authority: sync::WriteAuthority,
    ) -> Result<(), SyncError>;

    /// Consume peer pushes until the peer disconnects. Consumes the session.
    ///
    /// `session` carries the set this session subscribed in [`SyncSession::catch_up`] (pushed
    /// coins outside it are dropped, because a peer answers a subscription rather than defining
    /// one), its peer's trust level, and its rollback allowance.
    async fn run(
        self: Box<Self>,
        db: &WalletDb,
        events: &EventBus,
        session: &mut sync::SessionState<'_>,
    ) -> Result<(), SyncError>;
}

/// Corroborates a would-be writer's view of the chain against independently chosen peers
/// (dig_ecosystem#2568).
///
/// This is the seam that makes a DISCOVERED peer usable without making it trusted. The
/// supervisor holds exactly ONE subscription session — that constraint is unchanged, and its
/// reason (N interleaved `rollback_above` calls into a DB with one writer) is unchanged too — so
/// corroboration deliberately does NOT subscribe anywhere else. It opens short, read-only probes
/// to [`quorum::QUORUM_SAMPLE`] other randomly chosen peers, asks each the same settled-height
/// question, and closes them.
///
/// The writer is then elevated only if it AGREES with the corroborated answer. That ordering is
/// what makes "a single lying peer cannot move the replica" true by construction rather than by
/// vigilance: the liar is the one being checked, and it is checked before it writes.
#[async_trait::async_trait]
pub trait Corroborator: Send + Sync {
    /// Draw a fresh random sample, settle a height from THEIR claims alone, and ask each of them
    /// for the canonical header hash there.
    ///
    /// The writer is deliberately not an input. Every round draws a new sample
    /// ([`quorum::select_sample`]) rather than reusing the last one, so a peer that lost a round
    /// gains nothing by waiting for the retry.
    ///
    /// Returns the verdict AND the height it was reached at, so the caller can put the SAME
    /// question to the writer. An `Err` is a probing failure (nothing reachable), which is
    /// treated exactly as a refusal — never as consent.
    async fn corroborate(&self) -> Result<CorroborationRound, SyncError>;
}

/// One completed corroboration round: what was asked, and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorroborationRound {
    /// The settled height every peer in this round was asked about
    /// ([`quorum::common_height`]).
    pub height: u32,
    /// What the quorum concluded about the canonical header hash at that height.
    pub verdict: Verdict<Bytes32>,
}

/// Decide whether a writer may be elevated, given a corroboration round and the writer's own
/// answer at the same height.
///
/// Split out as a pure function with no I/O so the decision — the single line the whole trust
/// model now rests on — is exhaustively testable, and so it reads as one rule instead of being
/// spread across the supervisor's control flow.
///
/// Both conditions are required and neither is sufficient:
///
/// * the quorum must have REACHED a verdict (a [`Verdict::Split`] means the truth is unknown, and
///   an unknown truth elevates nobody), and
/// * the writer must AGREE with it. A writer that disagrees with an independently drawn quorum at
///   a settled height is the anomaly in the round, and handing it the replica because "a quorum
///   succeeded" would corroborate everyone except the peer actually doing the writing.
pub fn may_elevate(round: &CorroborationRound, writer_answer: Option<Bytes32>) -> bool {
    match (round.verdict.corroborated(), writer_answer) {
        (Some(agreed), Some(mine)) => agreed == &mine,
        _ => false,
    }
}

/// Evidence that the CHAIN advanced, drawn independently of the subscription session
/// (dig_ecosystem#2851).
///
/// The stall check needs a second opinion about time passing, and it must not come from the session
/// being judged: a parked session reports nothing, and nothing is not an accusation. The node's own
/// Chia peers — a different peer set, a different transport — are that second opinion.
///
/// It is a NARROW seam on purpose. [`super::fallback::ChainFallback`] can answer this question and
/// is the production implementation, but it also carries a dozen unrelated, non-defaulted methods,
/// so making the supervisor depend on it directly would make every test double heavy enough that
/// nobody writes one.
#[async_trait::async_trait]
pub trait ChainTipObserver: Send + Sync {
    /// The peak the node's OWN chia peers announced.
    ///
    /// `None` is UNOBSERVABLE — no transport, or no peer has said anything yet — and never a zero,
    /// which every block is trivially above.
    async fn peers_peak(&self) -> Option<u32>;
}

/// The production observer: the node's chain transport, asked for its peer tier.
pub struct FallbackChainTip(Arc<dyn super::fallback::ChainFallback>);

impl FallbackChainTip {
    /// Observe the chain tip through an existing chain-fallback transport.
    pub fn new(fallback: Arc<dyn super::fallback::ChainFallback>) -> Self {
        Self(fallback)
    }
}

#[async_trait::async_trait]
impl ChainTipObserver for FallbackChainTip {
    async fn peers_peak(&self) -> Option<u32> {
        self.0.peer_tier().await.peak_height
    }
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

/// Why a session stopped, which decides what the supervisor does next.
enum SessionOutcome {
    /// Shutdown was requested; the supervisor exits.
    Stop,
    /// The subscription set changed under a nothing-subscribed session; reconnect immediately.
    Resubscribe,
    /// The peer disconnected (or the loop errored); back off and retry.
    Ended,
    /// The session reached [`SESSION_MAX_LIFETIME`] (dig_ecosystem#2851). A PLANNED end, so — like
    /// [`Self::Resubscribe`] — it reconnects at once and the backoff ladder has nothing to say
    /// about it.
    Rotate,
}

/// Why a catch-up did not complete (dig_ecosystem#2851).
///
/// The three endings are kept apart because they mean different things to an operator and lead to
/// different places in the loop: a peer that REFUSED, a peer that never finished, and a node that
/// was asked to stop. Folding the middle one into the first would report a peer error that never
/// happened; folding the last into either would back off and reconnect on the way out.
enum CatchUpFailure {
    /// The peer refused, or the catch-up errored.
    Failed(SyncError),
    /// [`CATCH_UP_DEADLINE`] elapsed with the catch-up still running.
    TimedOut,
    /// Shutdown was requested; the supervisor exits without reconnecting.
    Stopped,
}

/// What one stall observation concluded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StallVerdict {
    /// The replica is following the chain, or nothing can be said about it.
    Following,
    /// It is following again, and the last thing the log said was that it had stopped.
    Recovered,
    /// It has been provably behind and still for `elapsed`, which is long enough to act on.
    Stalled { elapsed: Duration },
}

/// The replica's freeze, tracked ACROSS sessions (dig_ecosystem#2851).
///
/// It deliberately outlives any one session, and that is not an optimisation — it is what keeps the
/// deadline reachable at all.
///
/// NOT because rotation is fast. [`SESSION_MAX_LIFETIME`] is 600s against [`STALL_AFTER`]'s 90s, so
/// a session retired ON SCHEDULE has ample room to reach the deadline by itself. The reason is that
/// scheduled retirement is the one ending a session is LEAST likely to get: a session ends on a
/// disconnect, a failed catch-up, a refusal, a resubscribe or a rotation, and the first four arrive
/// on no schedule at all. A clock scoped to a session restarts at EVERY one of them, so a replica
/// frozen across a run of short sessions would never accumulate 90 seconds anywhere, and the
/// detector would be dead code that reads as a working guard — which is the state
/// [`tests::stall_evidence_survives_the_end_of_a_session`] exists to make unreachable.
///
/// A frozen replica is a property of the REPLICA anyway; which peer happened to be attached while
/// it froze is incidental to whether it moved.
///
/// Split out as a pure state machine with no I/O so every branch — including the ones that must NOT
/// accuse — is directly testable.
#[derive(Debug, Default)]
pub(crate) struct StallWatch {
    /// The replica peak at the previous observation, so "advanced" is a comparison rather than a
    /// guess.
    last_replica: Option<u32>,
    /// When the replica was first seen behind AND still. `None` means the clock is not running.
    stalled_since: Option<Instant>,
    /// Whether a stall was declared and its recovery has not yet been reported.
    recovery_unreported: bool,
}

impl StallWatch {
    /// Fold one observation in, and say what it means.
    ///
    /// Only POSITIVE evidence accuses: an unobservable height on either side, and a replica merely
    /// LEVEL with its peers, both reset the clock. A quiet chain and a node that cannot see the
    /// chain are ordinary, and neither is grounds for tearing down a working session.
    pub(crate) fn observe(
        &mut self,
        replica: Option<u32>,
        peers: Option<u32>,
        now: Instant,
    ) -> StallVerdict {
        let advanced =
            matches!((replica, self.last_replica), (Some(now), Some(before)) if now > before);
        self.last_replica = replica.or(self.last_replica);

        let behind = matches!((replica, peers), (Some(r), Some(p)) if p > r);
        if advanced || !behind {
            self.stalled_since = None;
            if advanced && std::mem::take(&mut self.recovery_unreported) {
                return StallVerdict::Recovered;
            }
            return StallVerdict::Following;
        }

        let since = *self.stalled_since.get_or_insert(now);
        let elapsed = now.duration_since(since);
        if elapsed >= STALL_AFTER {
            // Re-armed for the next episode: the clock restarts, and a recovery is now owed.
            self.stalled_since = None;
            self.recovery_unreported = true;
            return StallVerdict::Stalled { elapsed };
        }
        StallVerdict::Following
    }
}

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
    /// Elevates a DISCOVERED writer to [`PeerTrust::Corroborated`] when an independently drawn
    /// quorum agrees with it (dig_ecosystem#2568).
    ///
    /// `None` disables corroboration entirely, which reproduces the pre-#2568 behaviour exactly:
    /// a discovered peer contributes liveness and writes nothing. That is the honest default for
    /// a test or an offline host, and it is why the field is an `Option` rather than a
    /// no-op implementation — "corroboration is switched off" and "corroboration ran and refused"
    /// must not look the same in a stack trace.
    pub corroborator: Option<Arc<dyn Corroborator>>,
    /// Independent evidence that the chain advanced, used to end a session whose replica has
    /// stopped moving (dig_ecosystem#2851).
    ///
    /// `None` means NO STALL DETECTION AT ALL — stated as plainly as [`Self::corroborator`]'s
    /// `None` means no corroboration, and for the same reason: "the check is switched off" and
    /// "the check ran and found nothing" must not look the same. A supervisor built without one
    /// behaves exactly as it did before this field existed.
    pub chain_tip: Option<Arc<dyn ChainTipObserver>>,
    /// How long one session runs before it is retired. Production passes
    /// [`SESSION_MAX_LIFETIME`]; see that constant for the costs the number trades.
    ///
    /// Injected rather than read from the constant so a test can give rotation a DISTINCTIVE
    /// duration. The test clock returns from every sleep instantly, so a timer is identified ONLY
    /// by the duration it asked for, and a test that silences rotation by suppressing its duration
    /// silences every other timer asking for the same one. That collision was live while the
    /// lifetime was 60 seconds — [`BACKOFF_MAX`]'s value — and wedged a backoff wait; the lifetime
    /// has since moved to 600 seconds, so the two no longer collide, but the injection stays
    /// because the hazard belongs to the technique rather than to either number.
    pub session_lifetime: Duration,
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
        // Consecutive rounds that failed to reach a quorum. Reset by any round that does, so this
        // counts a STANDING disagreement rather than a lifetime total.
        let mut splits: u32 = 0;
        // The replica's freeze, tracked across sessions rather than within one — see
        // [`StallWatch`] for why that is required rather than merely tidy.
        let stall_watch = Mutex::new(StallWatch::default());

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
            //
            // A DISCOVERED peer subscribes nothing AND writes nothing, whatever the wallet holds:
            // its answers may never make the replica authoritative (`sync::PeerTrust`), and a
            // higher peak would inflate apparent confirmation counts (see [`sync::PeerTrust`]
            // for the inversion that made this the vulnerability). It runs as a write-free
            // session, which is what powers the live sync status.
            let authority = self.trust_for_session(&*session, &mut splits).await;
            let trust = authority.trust();
            // Publish the trust the INSTANT it is settled, before a subscription set is resolved
            // for it — the order the supervisor genuinely learns the two facts. Until
            // `set_watched` lands just below, the count is honestly unknown.
            handle.set_trust(trust.is_authoritative());
            let puzzle_hashes = match trust {
                PeerTrust::Operator | PeerTrust::Corroborated => self.puzzle_hashes.puzzle_hashes(),
                PeerTrust::Discovered => Vec::new(),
            };
            let subscribed: sync::SubscribedHashes = puzzle_hashes.iter().copied().collect();
            let nothing_subscribed = puzzle_hashes.is_empty();
            // The MEASUREMENT of the subscription set. Paired with the trust recorded above, the
            // phase can now tell "custody holds nothing" from "this writer was refused" — the two
            // produce an identical empty set here, and only the first is the benign
            // the two nothing-to-watch phases (dig_ecosystem#2609).
            // Enrollment is read from the MANIFEST, not from the set above: a locked wallet
            // contributes no hashes and is still enrolled, and that difference is the whole of
            // `WalletNotUnlocked`.
            handle.set_watched(puzzle_hashes.len() as u32, self.puzzle_hashes.any_wallet());
            if nothing_subscribed {
                // Nothing to subscribe. The session still runs: for an OPERATOR peer with an
                // empty puzzle-hash set, `new_peak_wallet` needs no subscription and the
                // replica's peak keeps advancing. A DISCOVERED peer subscribes nothing AND
                // writes nothing — its frames are dropped by `handle_coin_state_update` and
                // `run_update_loop` before any DB write, including the peak. In both cases
                // `is_synced()` stays false — the truth, and what keeps wallet-scoped reads on
                // the fallback tier. The session is also re-polled below, so a wallet created
                // after boot is subscribed within seconds rather than at the next disconnect.
                tracing::debug!("wallet sync: no custodied puzzle hashes; nothing subscribed");
            } else {
                let began = self.time.now();
                // A catch-up is the one long-running step the supervisor takes, and until
                // dig_ecosystem#2851 it took the whole loop with it: sitting outside this `select!`
                // it disarmed rotation, stall detection AND shutdown for its entire duration, which
                // a peer answering each round trip just inside its timeout could stretch to about
                // seventeen hours. Rotation and stall detection cannot meaningfully run here — both
                // end the session, and ending a session mid-catch-up discards the work — but a
                // TOTAL deadline and shutdown both can, and shutdown is not optional at any
                // duration.
                let catch_up = tokio::select! {
                    result = session.catch_up(
                        &self.db,
                        puzzle_hashes,
                        self.genesis_challenge,
                        &self.events,
                        authority,
                    ) => result.map_err(CatchUpFailure::Failed),
                    () = self.time.sleep(CATCH_UP_DEADLINE) => Err(CatchUpFailure::TimedOut),
                    // Dropping the `catch_up` future closes the peer. Nothing is aborted mid-write:
                    // the future is only dropped at an await point, and a DB write already in
                    // flight is not one.
                    _ = shutdown.changed() => Err(CatchUpFailure::Stopped),
                };
                match catch_up {
                    Ok(()) => {}
                    Err(CatchUpFailure::Stopped) => {
                        handle.set_connected(0);
                        break;
                    }
                    Err(failure) => {
                        match failure {
                            CatchUpFailure::Failed(e) => {
                                tracing::warn!(error = %e, "wallet sync: catch-up failed");
                            }
                            // Named as its own line because it is diagnostically nothing like a
                            // failed catch-up: the peer never refused anything, it simply never
                            // finished, and an operator seeing only "catch-up failed" would look
                            // for an error that does not exist.
                            CatchUpFailure::TimedOut => tracing::warn!(
                                peer = %session.peer_ip(),
                                deadline_secs = CATCH_UP_DEADLINE.as_secs(),
                                "wallet sync: the catch-up did not finish within its total \
                                 deadline; abandoning the session so a fresh peer is dialled"
                            ),
                            CatchUpFailure::Stopped => unreachable!("handled above"),
                        }
                        handle.set_connected(0);
                        if !self.wait(&mut backoff, &mut shutdown).await {
                            break;
                        }
                        continue;
                    }
                }
                // Reported on EVERY session, because it is the number that decides whether
                // [`SESSION_MAX_LIFETIME`] is affordable. A reconnect re-runs the catch-up from
                // genesis, which sounds expensive; measuring it turns the rotation cadence into a
                // question with an answer instead of an argument.
                tracing::info!(
                    peer = %session.peer_ip(),
                    catch_up_ms = self.time.now().duration_since(began).as_millis(),
                    "wallet sync: catch-up complete"
                );
            }

            // Taken before the session is moved into `run` below, so the stall and recovery lines
            // can both name the peer the episode was about.
            let peer_ip = session.peer_ip();
            let mut state = sync::SessionState::with_authority(&subscribed, authority);
            let outcome = tokio::select! {
                result = session.run(&self.db, &self.events, &mut state) => {
                    if let Err(e) = result {
                        tracing::warn!(error = %e, "wallet sync: update loop ended in error");
                    }
                    SessionOutcome::Ended
                }
                // A wallet appeared while this nothing-subscribed session was running. The
                // subscription is per-connection state, so the only way to subscribe it is a
                // new session. Only worth waiting for on a peer that could actually subscribe
                // them; a discovered peer subscribes nothing AND writes nothing however many
                // wallets appear.
                () = self.await_puzzle_hashes(nothing_subscribed && trust.is_authoritative())
                    => SessionOutcome::Resubscribe,
                // This session was REFUSED, and corroboration only runs at session start — so the
                // refusal is permanent for as long as the session lives. Ending it hands the
                // decision back to the reconnect path, which draws an independent sample and runs
                // the `Corroborator` again. That is what makes the "re-drawing a fresh sample" log
                // line above TRUE; no new retry mechanism is introduced (dig_ecosystem#2827).
                () = self.await_recorroboration(!trust.is_authoritative())
                    => SessionOutcome::Ended,
                // The peer went silent while the chain kept moving. `run` above is parked on a
                // `recv()` with no deadline, and for an AUTHORITATIVE subscribed session every
                // other arm here is disarmed by construction — so without this one the only exit
                // is a disconnect that a half-open connection never delivers
                // (dig_ecosystem#2851).
                () = self.await_stall(trust.is_authoritative(), &stall_watch, &peer_ip)
                    => SessionOutcome::Ended,
                // Every session is retired on a schedule, so no single peer becomes both the only
                // thing writing the replica and the only thing watching it. The timer necessarily
                // starts HERE, after the catch-up returned: truncating a legitimately long first
                // catch-up would guarantee a replica that never finishes, which is the failure this
                // whole ticket is about.
                () = self.await_session_rotation() => SessionOutcome::Rotate,
                // Dropping the `run` future drops the receiver, which closes the peer. No
                // abort, so any DB write already in flight completes first.
                _ = shutdown.changed() => SessionOutcome::Stop,
            };
            handle.set_connected(0);
            match outcome {
                SessionOutcome::Stop => break,
                // Reconnect at once: this is a user action, not a failure, so the backoff
                // ladder has nothing to say about it.
                SessionOutcome::Resubscribe => {
                    tracing::info!(
                        "wallet sync: custodied puzzle hashes appeared; reconnecting to subscribe"
                    );
                    backoff.reset();
                    continue;
                }
                SessionOutcome::Ended => {}
                // A planned retirement, so it reconnects at once and the ladder is reset
                // EXPLICITLY rather than left to the `HEALTHY_SESSION` check below. That check
                // would currently agree — a 600-second session comfortably clears a 60-second
                // threshold — but it is a threshold on how long a session HAPPENED to last, and
                // this is a statement that a planned end is not a failure. Deriving the second from
                // the first makes the rule true by arithmetic that either constant is free to
                // break.
                SessionOutcome::Rotate => {
                    tracing::info!(
                        peer = %peer_ip,
                        age_secs = self.time.now().duration_since(started).as_secs(),
                        "wallet sync: retiring the subscription session on schedule; dialling a \
                         fresh peer"
                    );
                    backoff.reset();
                    continue;
                }
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

    /// What this session is actually entitled to write: its dial-source trust, plus one chance to
    /// be elevated by corroboration (dig_ecosystem#2568) — and, when it is, the
    /// [`sync::PeakCeiling`] that elevation is only ever granted WITH (dig_ecosystem#2851).
    ///
    /// Ordering is the point. This runs BEFORE the catch-up and before any frame is handled, so a
    /// peer that fails corroboration never had a window in which its answers were already
    /// landing. Every refusal path returns [`PeerTrust::Discovered`], which writes nothing — a
    /// probe error, an unreachable quorum, a split, a writer that disagrees, and corroboration
    /// being switched off all fail the same, closed way.
    ///
    /// The ceiling is anchored on the round's own settled height, which is independent of the
    /// writer by construction: [`may_elevate`] requires the writer to AGREE with that height, so
    /// it is a floor the writer cannot inflate. It is fixed for the session and never ratchets —
    /// refreshing it is exactly what [`SESSION_MAX_LIFETIME`] rotation already does, which is the
    /// one place rotation REDUCES exposure rather than raising it.
    async fn trust_for_session(
        &self,
        session: &dyn SyncSession,
        splits: &mut u32,
    ) -> sync::WriteAuthority {
        let dialed = session.trust();
        if dialed != PeerTrust::Discovered {
            return match dialed {
                // The operator hand-configured this address, and corroboration only runs on the
                // discovery path below — so there is no independent anchor to build a ceiling
                // from, and inventing one would second-guess an explicit configuration.
                PeerTrust::Operator => sync::WriteAuthority::Operator,
                // Unreachable in practice: `trust()` reports the DIAL source, which is never
                // already-corroborated. Elevation is this function's own output.
                PeerTrust::Corroborated | PeerTrust::Discovered => sync::WriteAuthority::Discovered,
            };
        }
        let Some(corroborator) = self.corroborator.as_ref() else {
            return sync::WriteAuthority::Discovered;
        };

        let round = match corroborator.corroborate().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "wallet sync: corroboration probe failed; the peer                      stays uncorroborated and writes nothing");
                return sync::WriteAuthority::Discovered;
            }
        };

        // The writer answers the SAME question, at a height it did not choose.
        let writer_answer = match session.header_hash_at(round.height).await {
            Ok(answer) => answer,
            Err(e) => {
                tracing::debug!(error = %e, height = round.height, "wallet sync: the writer could                      not answer the corroboration question");
                None
            }
        };

        if !may_elevate(&round, writer_answer) {
            *splits = splits.saturating_add(1);
            let persistent = *splits >= quorum::PERSISTENT_DISAGREEMENT_ROUNDS;
            // A run of failures is not "the network is slow". A fresh random sample failing to
            // agree, repeatedly, is what a partition and a sustained attack both look like from a
            // light client, and retrying quietly forever would present both as a node that merely
            // never finishes syncing.
            if persistent {
                tracing::warn!(
                    consecutive = *splits,
                    height = round.height,
                    peer = %session.peer_ip(),
                    verdict = ?round.verdict,
                    "wallet sync: peers persistently disagree about settled chain state; the                      replica is deliberately NOT being written. This is evidence of a network                      partition or a hostile peer set, not of a slow connection."
                );
            } else {
                tracing::info!(
                    consecutive = *splits,
                    height = round.height,
                    verdict = ?round.verdict,
                    "wallet sync: no corroborated answer this round; re-drawing a fresh sample"
                );
            }
            return sync::WriteAuthority::Discovered;
        }

        *splits = 0;
        if let Verdict::MajorityWithDissent { dissenters, .. } = &round.verdict {
            // Surfaced, never averaged away: at a settled height, past the lag filter, a peer
            // contradicting the supermajority is not merely behind.
            tracing::warn!(
                height = round.height,
                ?dissenters,
                "wallet sync: a peer disagreed with the quorum about settled chain state"
            );
        }
        tracing::info!(
            height = round.height,
            peer = %session.peer_ip(),
            ceiling = round.height.saturating_add(sync::peak_allowance(self.session_lifetime)),
            "wallet sync: discovered peer corroborated by an independent quorum; it may now write"
        );
        // The allowance is derived from the lifetime this supervisor actually runs sessions for,
        // never the constant: `PeakCeiling`'s own doc says a hardcoded ceiling would silently
        // become too tight if the lifetime moved UP, and reading the constant here is exactly the
        // hardcoding it warns about (dig_ecosystem#2851, F3).
        sync::WriteAuthority::Corroborated(sync::PeakCeiling::from_corroborated(
            round.height,
            self.session_lifetime,
        ))
    }

    /// Resolve once the subscription set stops being empty.
    ///
    /// Returns a future that NEVER resolves when `poll` is false — a session that already
    /// subscribed has nothing to wait for, and its set is fixed for the life of the connection.
    async fn await_puzzle_hashes(&self, poll: bool) {
        if !poll {
            std::future::pending::<()>().await;
        }
        loop {
            self.time.sleep(PUZZLE_HASH_POLL).await;
            if !self.puzzle_hashes.puzzle_hashes().is_empty() {
                return;
            }
        }
    }

    /// Resolve once a REFUSED session has been held long enough to be worth re-corroborating.
    ///
    /// Returns a future that NEVER resolves when `retry` is false. An authoritative session has
    /// nothing to re-corroborate — it already cleared the quorum — and ending it would discard a
    /// live subscription and force a fresh catch-up from genesis, which is a worse failure than the
    /// one this exists to fix.
    async fn await_recorroboration(&self, retry: bool) {
        if !retry {
            std::future::pending::<()>().await;
        }
        self.time.sleep(RECORROBORATE_AFTER).await;
    }

    /// Resolve once this session has held the replica STILL for [`STALL_AFTER`] while the chain
    /// was observed to advance past it (dig_ecosystem#2851).
    ///
    /// Returns a future that NEVER resolves when `armed` is false, or when no
    /// [`ChainTipObserver`] was supplied. It is armed for AUTHORITATIVE sessions only: a
    /// [`PeerTrust::Discovered`] session never advances the peak BY DESIGN (it writes nothing), so
    /// arming it there would fire on every refused session and fight
    /// [`Self::await_recorroboration`], which already owns that exit.
    ///
    /// Every branch that is not POSITIVE evidence of a stall resets the clock. An unobservable
    /// height and a chain that is merely level with the replica are both perfectly ordinary, and
    /// neither is an accusation.
    ///
    /// This does NOT lower the corroboration bar. It only ENDS a session, handing the decision back
    /// to the ordinary reconnect path, which draws an independent sample and re-runs the
    /// [`Corroborator`] exactly as it always did (NC-12: peers stay untrusted, corroboration stays a
    /// confidence gradient, nothing blocks on N-of-N). §908: it reads two heights and signs nothing.
    async fn await_stall(&self, armed: bool, watch: &Mutex<StallWatch>, peer_ip: &str) {
        let Some(chain_tip) = self.chain_tip.as_ref().filter(|_| armed) else {
            std::future::pending::<()>().await;
            // `pending` never returns; this is unreachable and exists only to satisfy the type.
            return;
        };

        loop {
            self.time.sleep(STALL_POLL).await;

            let replica = self.db.sync_state().await.ok().and_then(|s| s.peak_height);
            let peers = chain_tip.peers_peak().await;
            let now = self.time.now();

            let verdict = {
                let mut watch = watch.lock().expect("stall watch poisoned");
                watch.observe(replica, peers, now)
            };
            match verdict {
                // The other half of the episode. The session that stalled logged a failure and then
                // ended; without this the log goes quiet again and "did it recover?" is answerable
                // only by polling the RPC — and silence is what let this defect hide for hours.
                StallVerdict::Recovered => tracing::info!(
                    peer = %peer_ip,
                    replica_peak = ?replica,
                    peers_peak = ?peers,
                    "wallet sync: the replica is advancing again after a stalled session was ended"
                ),
                StallVerdict::Following => {}
                StallVerdict::Stalled { elapsed } => {
                    tracing::warn!(
                        peer = %peer_ip,
                        replica_peak = ?replica,
                        peers_peak = ?peers,
                        stalled_for_secs = elapsed.as_secs(),
                        "wallet sync: the replica has not advanced while this node's own peers \
                         moved ahead of it; ending the session so a fresh peer is dialled"
                    );
                    return;
                }
            }
        }
    }

    /// Resolve once this session has lived its full [`SESSION_MAX_LIFETIME`].
    ///
    /// Armed for EVERY session, whatever its trust: this is a planned lifetime, not a failure
    /// detector, and a session that is behaving perfectly is exactly the one rotation exists to
    /// retire. It waits on the injected clock, so the cadence is testable without a test that
    /// actually sits for a minute.
    async fn await_session_rotation(&self) {
        self.time.sleep(self.session_lifetime).await;
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

/// HOW a peer connection was obtained — the only input the trust label is allowed to have.
///
/// Named as a type rather than left as a `bool` or an inline literal because the mapping below
/// is the single line the whole trust model rests on, and an inline literal is invisible: the
/// previous round's audit flipped `PeerTrust::Discovered` to `PeerTrust::Operator` at the
/// discovery call site and the entire crate's test suite stayed green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialSource {
    /// A `user_managed` row in the `peers` table: an address the OPERATOR typed in.
    UserManagedPeerRow,
    /// A DNS-introducer answer or the loopback probe — whoever answered first.
    Discovery,
}

/// The trust a peer earns from HOW it was reached, and from nothing else.
///
/// Deliberately total, pure, and `const`: it takes no peer input, so there is no argument a peer
/// can supply that changes its answer, and both arms are pinned by
/// [`tests::the_trust_label_is_fixed_by_the_dial_source`].
pub const fn trust_for(source: DialSource) -> PeerTrust {
    match source {
        DialSource::UserManagedPeerRow => PeerTrust::Operator,
        DialSource::Discovery => PeerTrust::Discovered,
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
                        trust: trust_for(DialSource::UserManagedPeerRow),
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
            trust: trust_for(DialSource::Discovery),
            receiver: tokio::sync::Mutex::new(Some(receiver)),
        }))
    }
}

/// The production [`Corroborator`]: repeated independent dials, heights compared, then one
/// settled question put to all of them (dig_ecosystem#2568).
///
/// # How a sample is drawn
///
/// Each member comes from calling `chia_query`'s `connect_random_peer` again — a fresh discovery
/// per member rather than one list carved up — so no single resolution step decides the whole
/// sample.
///
/// Two properties of that helper have to be compensated for HERE, because they would otherwise
/// silently collapse the quorum, and neither is hypothetical:
///
/// * **It tries `127.0.0.1` before anything else, unconditionally.** Any unprivileged co-resident
///   process that binds `8444` first is therefore the peer EVERY call returns — the loopback-probe
///   hazard [`PeerTrust`] already names. Four calls would yield four connections to one attacker
///   and a "unanimous" verdict from a sample of one.
/// * **It returns the FIRST address that connects** out of a concurrent batch. That is
///   latency-biased selection, and latency is something an attacker running a fast, always-up node
///   controls.
///
/// The compensation is DISTINCTNESS: an address already in this round's sample is discarded and
/// re-drawn, within [`MAX_PROBE_ATTEMPTS`]. That is not a tidiness rule — it is the difference
/// between four opinions and one opinion counted four times. A round that assembles fewer than
/// [`quorum::CORROBORATION_FLOOR`] answers yields [`Verdict::Insufficient`], which writes nothing.
///
/// # Over-subscribe, then pull back (dig_ecosystem#2827)
///
/// The round dials up to [`quorum::QUORUM_DIAL_WIDE`] distinct peers and asks
/// [`quorum::QUORUM_HOLD`] of them, chosen by [`quorum::hold_best`]. Dialling exactly as many as
/// the round needs leaves it no margin for a dial that is stale, slow, or gone by the time the
/// question is put — and having no margin is how a round that could have been answered was
/// discarded instead.
///
/// The residual bias is real and `SPEC.md` says so: a peer that is fast and always up remains
/// over-represented among the probes. This raises an attacker's cost; it does not remove the
/// advantage. Resolving the full introducer address list once and drawing from it with
/// [`quorum::select_sample`] is the stronger form and is the tracked follow-up.
pub struct ChiaQuorumCorroborator {
    network: chia_query::NetworkType,
    /// How long to wait for one probe's dial and for its peak announcement.
    timeout: Duration,
}

/// How many dial attempts one round may make while assembling [`quorum::QUORUM_DIAL_WIDE`]
/// DISTINCT peers.
///
/// Bounded because the distinctness compensation is a retry loop over a helper that may keep
/// returning the same address — a host with a co-resident full node returns localhost every single
/// time — and an unbounded retry there is a hang, not a defence.
///
/// Two attempts per dial rather than the three it was when the target was four: widening the
/// target to ten already multiplies the worst-case dial count, and a round that spends longer
/// failing is a round the replica spends longer not being written. A degenerate or hostile network
/// still degrades to "no corroboration, nothing written" rather than to a hang, which is the
/// property this bound exists for.
const MAX_PROBE_ATTEMPTS: usize = quorum::QUORUM_DIAL_WIDE * 2;

impl ChiaQuorumCorroborator {
    /// A mainnet corroborator.
    pub fn mainnet() -> Self {
        Self {
            network: chia_query::NetworkType::Mainnet,
            timeout: DIAL_TIMEOUT,
        }
    }

    /// Dial repeatedly, keeping the first [`quorum::QUORUM_DIAL_WIDE`] DISTINCT addresses together
    /// with each one's claimed peak.
    async fn probe(&self) -> Vec<(quorum::Candidate, chia_wallet_sdk::client::Peer)> {
        let Ok(tls) = chia_query::peer::connect::create_generated_tls() else {
            return Vec::new();
        };
        let mut sample: Vec<(quorum::Candidate, chia_wallet_sdk::client::Peer)> = Vec::new();

        for _ in 0..MAX_PROBE_ATTEMPTS {
            if sample.len() >= quorum::QUORUM_DIAL_WIDE {
                break;
            }
            let Ok((peer, addr, receiver)) =
                chia_query::peer::connect::connect_random_peer(self.network, &tls, self.timeout)
                    .await
            else {
                continue;
            };
            let id = addr.to_string();
            if sample.iter().any(|(c, _)| c.id == id) {
                // The same peer again. Counting it twice would let one node supply an entire
                // "independent" quorum, so it is discarded rather than admitted.
                continue;
            }
            let Some(claim) = await_peak(receiver, self.timeout).await else {
                continue;
            };
            sample.push((quorum::Candidate { id, claim }, peer));
        }
        sample
    }
}

/// Read a peer's claimed tip from the `new_peak_wallet` it announces after the handshake.
///
/// A CLAIM, never a fact: a light client cannot verify either field. It is used only to COMPARE
/// HEIGHTS — to exclude the badly-lagged, and to settle the height everyone is then asked about —
/// and never reaches the replica.
async fn await_peak(
    mut receiver: tokio::sync::mpsc::Receiver<chia::protocol::Message>,
    timeout: Duration,
) -> Option<quorum::PeakClaim> {
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => return None,
            message = receiver.recv() => {
                let message = message?;
                if message.msg_type == chia::protocol::ProtocolMessageTypes::NewPeakWallet {
                    let peak =
                        <chia::protocol::NewPeakWallet as chia::traits::Streamable>::from_bytes(
                            &message.data,
                        )
                        .ok()?;
                    return Some(quorum::PeakClaim {
                        height: peak.height,
                        header_hash: peak.header_hash,
                    });
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Corroborator for ChiaQuorumCorroborator {
    async fn corroborate(&self) -> Result<CorroborationRound, SyncError> {
        let probes = self.probe().await;

        // COMPARE THE HEIGHTS, in two steps, in this order. First exclude the badly-lagged, so a
        // peer that is merely behind never becomes a dissenting vote. Then settle the question at
        // a height every survivor passed some blocks ago — where a lagging-but-honest peer and a
        // fully caught-up one hold the SAME answer, so a disagreement can no longer be explained
        // by lag. That is the whole behind-versus-lying discriminator.
        //
        // Then PULL BACK: the dial was deliberately wide, and asking every peer it happened to
        // reach would spend the margin the wide dial exists to provide.
        let candidates: Vec<quorum::Candidate> = probes.iter().map(|(c, _)| c.clone()).collect();
        // REFUSED, not narrowed, when the credibility band discarded half or more of the peers
        // that made a claim: the band is median-anchored, so a coordinated half owns it and can
        // place it off the honest set entirely. The denominator is the peers that CLAIMED a peak,
        // never the dial target and never the peers that later answered — keying it on either of
        // those would refuse a thin honest round and freeze the replica again (#2827).
        let Some(eligible) = quorum::hold_best(
            &quorum::OsEntropy,
            &candidates,
            quorum::PEAK_LAG_TOLERANCE,
            quorum::QUORUM_HOLD,
        ) else {
            tracing::warn!(
                claimants = candidates.len(),
                "wallet sync: the credibility band excluded half or more of the peers that \
claimed a peak; the round is refused rather than run on the surviving side. A \
split claim set is what a coordinated peer group looks like from a light client."
            );
            return Err(SyncError::Peer(
                "credibility band split the claimants: refusing to corroborate from the \
surviving side"
                    .into(),
            ));
        };
        let Some(height) = quorum::common_height(&eligible, quorum::SETTLED_LAG) else {
            return Err(SyncError::Peer(
                "no settled height: too few reachable peers agreed on a credible chain tip".into(),
            ));
        };

        let mut responses = Vec::new();
        for (candidate, peer) in &probes {
            if !eligible.iter().any(|e| e.id == candidate.id) {
                continue;
            }
            // A probe that will not answer is simply ABSENT from the tally. It lowers the round's
            // confidence — `Verdict::agreed` is smaller — and it no longer discards the round,
            // which is what left a replica frozen while peers that HAD answered were ignored
            // (dig_ecosystem#2827).
            if let Ok(Some(answer)) = header_hash_from(peer, height).await {
                responses.push(quorum::Response {
                    peer: candidate.id.clone(),
                    answer,
                });
            }
        }

        Ok(CorroborationRound {
            height,
            verdict: quorum::tally(&responses),
        })
    }
}

/// Ask one peer for the canonical header hash at `height`.
///
/// SELF-VERIFYING (`quorum::SelfVerifying::HeaderBlockBinding`): the hash is COMPUTED from the
/// block the peer sent — `HeaderBlock::header_hash()` folds the block's own foliage — never read
/// out of a field the peer chose. So a peer cannot name a hash that does not belong to the block
/// it handed over; it can only send a DIFFERENT block, which is exactly the claim the quorum then
/// votes on. Verifying the binding locally and voting only on the remaining question is the split
/// this module is built around.
async fn header_hash_from(
    peer: &chia_wallet_sdk::client::Peer,
    height: u32,
) -> Result<Option<Bytes32>, SyncError> {
    use chia::protocol::{RejectHeaderRequest, RequestBlockHeader, RespondBlockHeader};

    let response = peer
        .request_fallible::<RespondBlockHeader, RejectHeaderRequest, _>(RequestBlockHeader::new(
            height,
        ))
        .await
        .map_err(|e| SyncError::Peer(e.to_string()))?;

    Ok(match response {
        Ok(respond) => Some(respond.header_block.header_hash()),
        Err(_reject) => None,
    })
}

/// One live `chia-wallet-sdk` peer connection.
struct ChiaPeerSession {
    peer: chia_wallet_sdk::client::Peer,
    ip: String,
    /// Set by the factory from HOW this peer was reached: an operator's `peers` row, or
    /// discovery. Never from anything the peer itself claims.
    trust: PeerTrust,
    /// Taken by [`SyncSession::run`]. Behind a mutex only because the trait's `catch_up` takes
    /// `&self`; exactly one `run` ever consumes it.
    receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<chia::protocol::Message>>>,
}

#[async_trait::async_trait]
impl SyncSession for ChiaPeerSession {
    fn peer_ip(&self) -> String {
        self.ip.clone()
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
        authority: sync::WriteAuthority,
    ) -> Result<(), SyncError> {
        // The EFFECTIVE authority, not `self.trust`: a corroborated discovered peer must reach the
        // floor check as corroborated, or clearing the quorum would buy it nothing.
        sync::initial_sync_with_authority(
            &self.peer,
            db,
            puzzle_hashes,
            genesis_challenge,
            &self.ip,
            events,
            authority,
        )
        .await
    }

    async fn header_hash_at(&self, height: u32) -> Result<Option<Bytes32>, SyncError> {
        // Deliberately the SAME helper the corroboration probes use: the writer and the quorum
        // must be asked identically, or comparing their answers compares two different questions.
        header_hash_from(&self.peer, height).await
    }

    async fn run(
        self: Box<Self>,
        db: &WalletDb,
        events: &EventBus,
        session: &mut sync::SessionState<'_>,
    ) -> Result<(), SyncError> {
        let receiver = self
            .receiver
            .lock()
            .await
            .take()
            .ok_or_else(|| SyncError::Peer("sync session already consumed".into()))?;
        sync::run_update_loop(db, receiver, events, None, session).await
    }
}

#[cfg(test)]
mod tests;
