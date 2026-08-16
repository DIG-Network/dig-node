//! Profile-body persistence and propagation — opcodes 223/224/225 (epic #3008, W6).
//!
//! # What this module is
//!
//! A dig-profile's readable content is a **DPB artifact**: `magic "DIGP" ‖ version ‖ record*`, the
//! portable byte format `dig_social_profile::body` defines. This module is where a DPB **lands on
//! disk** and how it **travels between nodes**.
//!
//! Three legs, all carried on the ordinary gossip transport:
//!
//! | Opcode | Direction | This module's part |
//! |---|---|---|
//! | 223 `profile-root-announce` | public flood | hear it; ask a peer for the body behind it. Emit one after accepting a body. |
//! | 224 `profile-body-request` | directed, inbound | [`serve_body_request`] answers from disk, within an outbound budget. |
//! | 225 `profile-body` | directed, inbound | [`accept_body`] runs the gate, then persists. |
//!
//! # ONE encoding, at every boundary
//!
//! The bytes written to disk, the bytes carried in a 225 frame, and the bytes hashed to the
//! on-chain root are the **same bytes**. Nothing re-encodes anywhere. That is what makes a body
//! written by one machine byte-identical to the body another machine reads, and therefore what lets
//! any node serve any profile it holds without knowing anything about the publisher. Re-encoding at
//! a boundary would produce a different root and silently break sync.
//!
//! # The on-chain root is the ONLY authority
//!
//! A 223 announce is unsigned and a 225 body is attacker-chosen; neither carries any authority.
//! **Nothing is ever accepted except against a root this node resolved from chain itself**, through
//! [`AnchoredRootResolver`](crate::AnchoredRootResolver). The gate therefore **fails closed**: a
//! chain that cannot be read yields no root, and with no root there is nothing to compare against,
//! so nothing is accepted. `dig_social_profile::VerifiedBody::open` performs the comparison — this
//! module never hand-rolls a root check.
//!
//! # Verify against the REQUESTED root, never a re-read tip
//!
//! This node only ever asks for a root it already resolved from chain ([`Solicitations::record`]),
//! and stores the answer under **that** root. Re-reading the tip when the answer lands would create
//! two false branches at once: an honest peer penalized because the chain advanced mid-window, and
//! an ambiguity between a rollback and a race. Pinning the requested root removes both.
//!
//! # Penalization is narrow on purpose
//!
//! [`PeerPenalty::penalize`] fires in exactly ONE case: a body that fails to hash to the root *that
//! peer was asked for*. A late, duplicate, or entirely unsolicited answer is **dropped silently**.
//! Widening this would turn a multi-peer fan-out into an eclipse primitive — an attacker who can
//! make honest peers answer late (or forge an unsolicited frame attributed to them) could evict
//! every honest peer from the pool by doing nothing but being slow.
//!
//! # Slice 1 binds content to a STORE, never to a DID
//!
//! Nothing in the 223/224/225 frames carries a DID↔store pairing proof, and store descriptions are
//! forgeable (`dig_social_profile::pairing`'s own module docs say so outright). So the cache here is
//! keyed **`(store_id, root)` with no DID index**, and there is deliberately no `by_did` accessor —
//! do not add one. In particular `BLS_G1_PUBLIC_KEY` (0x0010), `PEER_ID` (0x0012) and `KEY_EPOCH`
//! (0x0013) MUST NOT be resolved out of this cache by any resolver: key resolution keeps going
//! through `dig_social_profile::resolve`, which does the pairing on chain.
//!
//! # Deliberately OUTSIDE `<cache>/modules/`
//!
//! Bodies live at `<cache>/profiles/<store_hex>/<root_hex>.dpb`. Capsules live under
//! `<cache>/modules/`, which `refresh_inventory` enumerates to build this node's DHT provider
//! records. A profile under that tree would become a phantom capsule provider record and perturb the
//! reshare flywheel, so the two trees are siblings and never overlap.
//!
//! # §908
//!
//! The node persists, serves and fetches. It never signs a profile and never edits one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_gossip::service::profile_sync::{
    frame_profile_body, frame_profile_body_request, frame_profile_root_announce, ProfileBody,
    ProfileRootRef, MAX_PROFILE_BODY_BYTES,
};
use dig_gossip::{Bytes32, PeerId};
use dig_social_profile::{AnchoredRoot, VerifiedBody};

use crate::AnchoredRootResolver;

/// Operator kill switch for the whole profile-sync subsystem, default ON.
///
/// Off means this node neither ingests nor serves profile bodies. Nothing else depends on this
/// having run — profiles simply stop syncing — so it is a clean degradation, not an outage.
pub const PROFILE_SYNC_ENV: &str = "DIG_NODE_PROFILE_SYNC";

/// Whether profile sync is enabled. Default ON; `0`/`false`/`off`/`no` (case-insensitive) disable it.
#[must_use]
pub fn profile_sync_enabled() -> bool {
    match std::env::var(PROFILE_SYNC_ENV) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

/// How long a recorded solicitation stays answerable.
///
/// Long enough for a slow peer over a relayed circuit, short enough that a stale entry cannot be
/// used to attribute a much later frame to a peer that has since been replaced in the pool.
pub const SOLICITATION_TTL: Duration = Duration::from_secs(120);

/// Maximum number of 225 answers this node will emit per inbound-request burst window.
///
/// A 224 request is cheap to send and expensive to answer (a disk read plus up to
/// [`MAX_PROFILE_BODY_BYTES`] on the wire), so an unbudgeted responder is an amplifier. The budget
/// is per-window across ALL peers because the scarce resource being protected is this node's own
/// upload, not any single link's fairness.
pub const OUTBOUND_BODY_BUDGET: usize = 32;

/// The window the [`OUTBOUND_BODY_BUDGET`] refills over.
pub const OUTBOUND_BUDGET_WINDOW: Duration = Duration::from_secs(10);

/// File extension of a persisted profile body.
pub const DPB_EXTENSION: &str = "dpb";

/// Directory, under the cache root, holding every persisted profile body.
///
/// A SIBLING of `modules/`, never a child — see the module docs.
pub const PROFILES_DIR: &str = "profiles";

// ---------------------------------------------------------------------------------------------
// On-disk store
// ---------------------------------------------------------------------------------------------

/// The on-disk profile-body cache: `<root>/<store_hex>/<root_hex>.dpb`.
///
/// Holds the DPB bytes **exactly as received** (see the module docs on one encoding at every
/// boundary). Writes are temp-file-plus-atomic-rename, so a concurrent reader sees either the whole
/// previous artifact or the whole new one and never a partial file. Retention is
/// **current-plus-one**: the body just written plus the most recently modified other, so a reader
/// mid-fetch of the previous generation is not raced into a missing file while the tree still
/// bounds to two artifacts per store.
///
/// Both path components are hex of 32 raw bytes produced by this crate, so a traversal component
/// (`..`, a separator, an absolute prefix) is unrepresentable by construction rather than filtered.
#[derive(Debug, Clone)]
pub struct ProfileBodyStore {
    root: PathBuf,
}

impl ProfileBodyStore {
    /// A store rooted at `dir` (which is created lazily on first write).
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { root: dir }
    }

    /// The store at `<cache_dir>/profiles`.
    #[must_use]
    pub fn under_cache_dir(cache_dir: &Path) -> Self {
        Self::new(cache_dir.join(PROFILES_DIR))
    }

    /// The directory holding every generation of `store_id`.
    #[must_use]
    pub fn store_dir(&self, store_id: &[u8; 32]) -> PathBuf {
        self.root.join(hex::encode(store_id))
    }

    /// The path a body for `(store_id, root)` occupies.
    #[must_use]
    pub fn path(&self, store_id: &[u8; 32], root: &[u8; 32]) -> PathBuf {
        self.store_dir(store_id)
            .join(format!("{}.{DPB_EXTENSION}", hex::encode(root)))
    }

    /// Whether a body for `(store_id, root)` is held.
    #[must_use]
    pub fn has(&self, store_id: &[u8; 32], root: &[u8; 32]) -> bool {
        self.path(store_id, root).is_file()
    }

    /// Read the body held for `(store_id, root)`.
    ///
    /// `Ok(None)` means "consulted, holds nothing"; `Err` means the read itself failed. The two need
    /// opposite remedies from a caller, so they are never collapsed.
    pub fn get(&self, store_id: &[u8; 32], root: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(store_id, root)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Persist `bytes` as the body for `(store_id, root)`, then prune to current-plus-one.
    ///
    /// `bytes` are written verbatim — this method never re-encodes. The caller is responsible for
    /// having obtained them from a [`VerifiedBody`], which is what ties the filename to the content.
    pub fn put(
        &self,
        store_id: &[u8; 32],
        root: &[u8; 32],
        bytes: &[u8],
    ) -> std::io::Result<PathBuf> {
        let dir = self.store_dir(store_id);
        std::fs::create_dir_all(&dir)?;
        let final_path = self.path(store_id, root);

        // A unique temp name per attempt: two processes sharing this cache dir (the OS service and
        // an in-process browser node) may write the same body concurrently, and a shared temp name
        // would let one truncate the other's half-written file before its own rename.
        let temp = dir.join(format!(
            ".{}.{}.{}.tmp",
            hex::encode(root),
            std::process::id(),
            unique_suffix()
        ));
        std::fs::write(&temp, bytes)?;
        // Rename is atomic within a directory and REPLACES an existing file on every platform this
        // node ships to, so a re-receipt of the same body is idempotent rather than an error.
        if let Err(e) = std::fs::rename(&temp, &final_path) {
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }
        self.prune_keeping(&dir, &final_path);
        Ok(final_path)
    }

    /// Every root held for `store_id`, in unspecified order.
    #[must_use]
    pub fn roots_for_store(&self, store_id: &[u8; 32]) -> Vec<[u8; 32]> {
        let Ok(entries) = std::fs::read_dir(self.store_dir(store_id)) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| root_from_file_name(&e.file_name().to_string_lossy()))
            .collect()
    }

    /// Delete every artifact in `dir` except `keep` and the most recently modified other.
    ///
    /// Best-effort: a failure to enumerate or unlink leaves extra bodies on disk, which costs disk
    /// and nothing else, so it is never surfaced as an error on the accept path.
    fn prune_keeping(&self, dir: &Path, keep: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut others: Vec<(std::time::SystemTime, PathBuf)> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p != keep && root_from_file_name(&file_name_of(p)).is_some())
            .map(|p| {
                let mtime = std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                (mtime, p)
            })
            .collect();
        // Newest first, so `skip(1)` retains exactly the single most recent predecessor.
        others.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, path) in others.into_iter().skip(1) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The file name of `path`, or an empty string — used only for the `.dpb` filter.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Parse `<64-hex>.dpb` back into the 32 root bytes it names, or `None` for anything else.
///
/// Deliberately strict: a temp file, a stray artifact, or a differently-cased name is NOT a body,
/// so retention and enumeration never act on a file this module did not write.
fn root_from_file_name(name: &str) -> Option<[u8; 32]> {
    let stem = name.strip_suffix(&format!(".{DPB_EXTENSION}"))?;
    if stem.len() != 64 || !stem.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return None;
    }
    let raw = hex::decode(stem).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

/// A monotonic-ish suffix distinguishing two temp files written in the same process.
fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------------------------
// Solicitation ledger
// ---------------------------------------------------------------------------------------------

/// The set of `(store_id, root)` requests this node has outstanding, and which peers were asked.
///
/// A recorded root is **always** one this node resolved from chain before asking — that invariant is
/// established at the single call site ([`request_body`]) and is what makes "verify against the
/// requested root" equivalent to "verify against chain".
#[derive(Clone, Default)]
pub struct Solicitations {
    inner: Arc<Mutex<HashMap<([u8; 32], [u8; 32]), Vec<(PeerId, Instant)>>>>,
}

impl Solicitations {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer` was asked for the body behind `(store_id, root)`.
    pub fn record(&self, store_id: [u8; 32], root: [u8; 32], peer: PeerId) {
        let mut guard = self.locked();
        let entry = guard.entry((store_id, root)).or_default();
        entry.retain(|(_, at)| at.elapsed() < SOLICITATION_TTL);
        entry.push((peer, Instant::now()));
    }

    /// Whether `peer` currently has an unexpired outstanding request for `(store_id, root)`.
    ///
    /// A read, not a take: a fan-out to several peers must stay answerable by each of them, and
    /// consuming the record on first answer would make every slower honest peer look unsolicited.
    #[must_use]
    pub fn is_solicited(&self, store_id: &[u8; 32], root: &[u8; 32], peer: &PeerId) -> bool {
        self.locked()
            .get(&(*store_id, *root))
            .is_some_and(|asked| {
                asked
                    .iter()
                    .any(|(p, at)| p == peer && at.elapsed() < SOLICITATION_TTL)
            })
    }

    /// Forget every request for `(store_id, root)` — called once the body is accepted.
    pub fn clear(&self, store_id: &[u8; 32], root: &[u8; 32]) {
        self.locked().remove(&(*store_id, *root));
    }

    /// The guarded map, recovering from poisoning rather than propagating a panic: the only code
    /// holding this guard is map access, so a poisoned lock cannot mean a half-applied mutation.
    fn locked(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<([u8; 32], [u8; 32]), Vec<(PeerId, Instant)>>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A refilling token budget bounding how many 225 answers this node emits per window.
#[derive(Clone)]
pub struct OutboundBudget {
    inner: Arc<Mutex<(usize, Instant)>>,
    capacity: usize,
    window: Duration,
}

impl Default for OutboundBudget {
    fn default() -> Self {
        Self::new(OUTBOUND_BODY_BUDGET, OUTBOUND_BUDGET_WINDOW)
    }
}

impl OutboundBudget {
    /// A budget of `capacity` answers per `window`.
    #[must_use]
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new((capacity, Instant::now()))),
            capacity,
            window,
        }
    }

    /// Take one token, returning `false` when the window's budget is exhausted.
    pub fn take(&self) -> bool {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (remaining, since) = &mut *guard;
        if since.elapsed() >= self.window {
            *remaining = self.capacity;
            *since = Instant::now();
        }
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        true
    }
}

// ---------------------------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------------------------

/// The set of stores whose profiles this node wants. Backed by `<cache>/subscriptions.json`.
pub trait SubscriptionView: Send + Sync {
    /// Whether this node is subscribed to `store_id`.
    fn is_subscribed(&self, store_id: &[u8; 32]) -> bool;
}

/// The gossip transport this module drives: one broadcast and one directed send.
#[async_trait::async_trait]
pub trait ProfileTransport: Send + Sync {
    /// Flood a 223 announce to every peer except `exclude`. Returns peers reached.
    async fn announce_root(&self, root_ref: &ProfileRootRef, exclude: Option<PeerId>) -> usize;
    /// Send one directed frame to `peer`. Best-effort.
    async fn send_body(&self, peer: PeerId, body: &ProfileBody);
    /// Send one directed 224 request to `peer`. Best-effort; `false` if it could not be sent.
    async fn send_request(&self, peer: PeerId, root_ref: &ProfileRootRef) -> bool;
    /// Peers currently live enough to ask.
    fn live_peers(&self) -> Vec<PeerId>;
}

/// Demotion of a peer that provably lied. See the module docs on why this is narrow.
#[async_trait::async_trait]
pub trait PeerPenalty: Send + Sync {
    /// `peer` answered a request with a body that does not hash to the root it was asked for.
    async fn penalize(&self, peer: PeerId, reason: &str);
}

// ---------------------------------------------------------------------------------------------
// The accept gate
// ---------------------------------------------------------------------------------------------

/// The outcome of offering one profile body to the gate. Every variant but
/// [`Accepted`](AcceptOutcome::Accepted) means nothing was written and nothing was announced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// Verified against the chain-resolved root, persisted, and announced to `announced` peers.
    Accepted {
        /// Size of the persisted DPB artifact.
        bytes: usize,
        /// Peers the follow-on 223 announce reached.
        announced: usize,
    },
    /// No outstanding request from this peer for this `(store_id, root)` — dropped silently, and
    /// **never penalized**: a late or duplicate honest answer is indistinguishable from a forged one.
    Unsolicited,
    /// This node is not subscribed to the store.
    NotSubscribed,
    /// The body exceeds the accepted size bound.
    TooLarge,
    /// The bytes do not hash to the root the peer was asked for. The ONE penalizing outcome.
    RootMismatch,
    /// The artifact was already held at this root — idempotent, no rewrite, no re-announce.
    AlreadyHeld,
    /// Persisting failed locally. Says nothing about the peer.
    PersistFailed,
}

/// Run the full accept gate for a 225 body that arrived from `sender`.
///
/// The order is load-bearing, each gate strictly cheaper than the next so a flood costs the least
/// possible work:
///
/// 1. **solicited?** — `(store_id, root, sender)` must be an outstanding request. O(local), no
///    hashing, no disk. Drops silently.
/// 2. **subscribed?** — O(local).
/// 3. **bounded?** — a length check before any allocation-heavy decode.
/// 4. **matches the CHAIN-RESOLVED root?** — [`VerifiedBody::open`] against the root recorded at
///    request time, which was resolved from chain. This is the only authority, and the only gate
///    whose failure penalizes.
/// 5. **persist** the verified bytes verbatim, then **announce once**, excluding `sender`.
pub async fn accept_body(
    store: &ProfileBodyStore,
    subs: &dyn SubscriptionView,
    solicitations: &Solicitations,
    transport: &dyn ProfileTransport,
    penalty: &dyn PeerPenalty,
    sender: PeerId,
    body: &ProfileBody,
) -> AcceptOutcome {
    let store_id: [u8; 32] = body.store_id.into();
    let root: [u8; 32] = body.root.into();

    // Gate 1 — solicited? The DoS guard AND the eclipse guard: an unsolicited frame costs one map
    // lookup and, critically, cannot cost its apparent sender a demotion.
    if !solicitations.is_solicited(&store_id, &root, &sender) {
        return AcceptOutcome::Unsolicited;
    }
    // Gate 2 — wanted?
    if !subs.is_subscribed(&store_id) {
        return AcceptOutcome::NotSubscribed;
    }
    // Gate 3 — bounded, before any parse.
    if body.body.len() > MAX_PROFILE_BODY_BYTES {
        return AcceptOutcome::TooLarge;
    }
    // Gate 4 — the chain-resolved root is the authority. `root` was resolved from chain BEFORE this
    // node asked for it (see `request_body`), so pinning it here is exactly a chain comparison —
    // without re-reading a tip that may have advanced since, which would penalize an honest peer for
    // being slow.
    let Ok(verified) = VerifiedBody::open(&body.body, AnchoredRoot::from_chain_read(root)) else {
        penalty
            .penalize(
                sender,
                "profile body does not hash to the root this peer was asked for",
            )
            .await;
        return AcceptOutcome::RootMismatch;
    };
    if store.has(&store_id, &root) {
        solicitations.clear(&store_id, &root);
        return AcceptOutcome::AlreadyHeld;
    }
    // Persist the VERIFIED bytes. `as_bytes` is the canonical serialization `VerifiedBody` committed
    // to when it accepted them, so disk, wire and chain-root all agree byte-for-byte.
    let bytes = verified.as_bytes();
    if let Err(e) = store.put(&store_id, &root, bytes) {
        tracing::warn!(error = %e, store = %hex::encode(store_id), "profile body persist failed");
        return AcceptOutcome::PersistFailed;
    }
    solicitations.clear(&store_id, &root);
    let announced = transport
        .announce_root(
            &ProfileRootRef {
                store_id: body.store_id,
                root: body.root,
            },
            Some(sender),
        )
        .await;
    AcceptOutcome::Accepted {
        bytes: bytes.len(),
        announced,
    }
}

/// Accept a body that arrived from a LOCAL caller (`control.profile.putBody`) rather than a peer.
///
/// The app is a caller like any other and gets no exemption: this resolves the root on chain
/// itself, requires the caller's declared root to BE that root, and then runs the same
/// [`VerifiedBody::open`] comparison the gossip gate runs. There is no solicitation gate because
/// there was no request — the chain check does all the work.
///
/// `Err` is the ONLY refusal: a rejected body must never look like a success with a flag.
pub async fn accept_local_body(
    store: &ProfileBodyStore,
    resolver: &dyn AnchoredRootResolver,
    store_id: [u8; 32],
    declared_root: [u8; 32],
    bytes: &[u8],
) -> Result<PathBuf, LocalAcceptError> {
    let chain_root = chain_root_for(resolver, &store_id).await?;
    if chain_root != declared_root {
        return Err(LocalAcceptError::RootNotConfirmed(format!(
            "root {} is not this store's confirmed on-chain root {} — the chain is the authority",
            hex::encode(declared_root),
            hex::encode(chain_root)
        )));
    }
    VerifiedBody::open(bytes, AnchoredRoot::from_chain_read(chain_root))
        .map_err(|e| LocalAcceptError::Malformed(e.to_string()))?;
    store
        .put(&store_id, &chain_root, bytes)
        .map_err(|e| LocalAcceptError::Persist(e.to_string()))
}

/// Why a locally-offered profile body was refused.
///
/// The three variants need OPPOSITE remedies from the caller — wait, fix the bytes, or look at the
/// node's disk — so they are deliberately not one string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAcceptError {
    /// The chain does not confirm this root (unreachable, no generation yet, or a different tip).
    /// The caller should WAIT and retry, not re-encode.
    RootNotConfirmed(String),
    /// The bytes are not a well-formed DPB, or do not hash to the confirmed root. Fix the bytes.
    Malformed(String),
    /// The node could not write the artifact. Nothing to do with the caller's input.
    Persist(String),
}

impl std::fmt::Display for LocalAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootNotConfirmed(m) | Self::Malformed(m) | Self::Persist(m) => f.write_str(m),
        }
    }
}

/// Resolve `store_id`'s current on-chain root, failing closed.
///
/// An unreachable chain and a store with no confirmed generation are BOTH refusals: with no root
/// there is nothing to compare against, so nothing may be accepted.
async fn chain_root_for(
    resolver: &dyn AnchoredRootResolver,
    store_id: &[u8; 32],
) -> Result<[u8; 32], LocalAcceptError> {
    match resolver.anchored_root(store_id).await {
        // `AnchoredRootResolver` speaks digstore's `Bytes32`, which wraps the raw 32 bytes; the wire
        // and the DPB format speak those bytes directly. Every comparison downstream is therefore
        // over `[u8; 32]`, never over hex text (case- and length-forgiving text comparison is exactly
        // the bypass `module_anchor`'s rule 2 forbids).
        Ok(Some(root)) => Ok(root.0),
        Ok(None) => Err(LocalAcceptError::RootNotConfirmed(
            "store has no confirmed on-chain generation yet (the chain is the authority)".into(),
        )),
        Err(e) => Err(LocalAcceptError::RootNotConfirmed(format!(
            "chain unreachable, so no root can be confirmed (fail closed): {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------------------------
// The 224 responder and the 223-driven fetch
// ---------------------------------------------------------------------------------------------

/// Whether a 224 request was answered, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    /// A 225 answer carrying `bytes` was sent.
    Served(usize),
    /// This node does not hold that `(store_id, root)`.
    NotHeld,
    /// The held artifact will not fit a 225 frame, so no frame was emitted.
    TooLargeToFrame,
    /// The outbound budget for this window is exhausted.
    Throttled,
    /// The artifact could not be read off disk.
    ReadFailed,
}

/// Answer one inbound 224 request from `peer`, within the outbound budget.
///
/// The budget is taken only once the artifact is known to exist, so a flood of requests for content
/// this node does not hold cannot starve the budget for peers asking about content it does.
pub async fn serve_body_request(
    store: &ProfileBodyStore,
    transport: &dyn ProfileTransport,
    budget: &OutboundBudget,
    peer: PeerId,
    request: &ProfileRootRef,
) -> ServeOutcome {
    let store_id: [u8; 32] = request.store_id.into();
    let root: [u8; 32] = request.root.into();
    if !store.has(&store_id, &root) {
        return ServeOutcome::NotHeld;
    }
    if !budget.take() {
        return ServeOutcome::Throttled;
    }
    let bytes = match store.get(&store_id, &root) {
        Ok(Some(bytes)) => bytes,
        // Raced against a prune between `has` and `get` — indistinguishable from not held, and
        // equally not the requester's problem.
        Ok(None) => return ServeOutcome::NotHeld,
        Err(e) => {
            tracing::warn!(error = %e, "profile body read failed answering a 224 request");
            return ServeOutcome::ReadFailed;
        }
    };
    let len = bytes.len();
    let body = ProfileBody {
        store_id: request.store_id,
        root: request.root,
        body: bytes,
    };
    // `frame_profile_body` refuses to emit a frame the receiver's limiter would drop, so an
    // over-large profile fails visibly here rather than silently at every peer.
    if frame_profile_body(&body).is_none() {
        return ServeOutcome::TooLargeToFrame;
    }
    transport.send_body(peer, &body).await;
    ServeOutcome::Served(len)
}

/// Ask one live peer for the body behind a root this node has ALREADY resolved from chain.
///
/// `root` MUST come from [`AnchoredRootResolver`] — that is the invariant [`accept_body`]'s gate 4
/// relies on, and this is the one function that establishes it. `exclude` skips the peer an announce
/// arrived from only when we have somewhere else to ask; otherwise asking the announcer is correct.
///
/// Returns the peer asked, or `None` if there was nobody to ask.
pub async fn request_body(
    transport: &dyn ProfileTransport,
    solicitations: &Solicitations,
    store_id: [u8; 32],
    root: [u8; 32],
) -> Option<PeerId> {
    let peers = transport.live_peers();
    let peer = peers.first().copied()?;
    let root_ref = ProfileRootRef {
        store_id: Bytes32::from(store_id),
        root: Bytes32::from(root),
    };
    // Recorded BEFORE the send: a peer that answers faster than this task resumes must still find
    // its answer solicited, or a fast honest peer would be dropped as unsolicited.
    solicitations.record(store_id, root, peer);
    if transport.send_request(peer, &root_ref).await {
        Some(peer)
    } else {
        None
    }
}

/// React to a 223 announce: if this node wants the store and does not already hold that root, and
/// the CHAIN agrees the root is the store's current generation, ask a peer for the body.
///
/// The chain read happens HERE, before any request, which is what makes the recorded solicitation
/// root a chain-resolved root. An announce naming a root the chain does not confirm costs an
/// attacker one ignored frame and this node one bounded chain query.
pub async fn handle_root_announce(
    store: &ProfileBodyStore,
    subs: &dyn SubscriptionView,
    resolver: &dyn AnchoredRootResolver,
    transport: &dyn ProfileTransport,
    solicitations: &Solicitations,
    announce: &ProfileRootRef,
) -> Option<PeerId> {
    let store_id: [u8; 32] = announce.store_id.into();
    let announced_root: [u8; 32] = announce.root.into();
    if !subs.is_subscribed(&store_id) {
        return None;
    }
    if store.has(&store_id, &announced_root) {
        return None;
    }
    let chain_root = chain_root_for(resolver, &store_id).await.ok()?;
    if chain_root != announced_root {
        return None;
    }
    request_body(transport, solicitations, store_id, chain_root).await
}

// ---------------------------------------------------------------------------------------------
// The ingest task
// ---------------------------------------------------------------------------------------------

/// Everything the ingest loop needs, grouped so the loop signature stays readable.
#[derive(Clone)]
pub struct ProfileSyncContext {
    /// The on-disk body cache.
    pub store: ProfileBodyStore,
    /// The set of stores whose profiles this node wants.
    pub subs: Arc<dyn SubscriptionView>,
    /// The node's chain view — the only root authority.
    pub resolver: Arc<dyn AnchoredRootResolver>,
    /// The gossip transport.
    pub transport: Arc<dyn ProfileTransport>,
    /// Demotion for a peer that provably lied.
    pub penalty: Arc<dyn PeerPenalty>,
    /// Outstanding requests, keyed `(store_id, root)`.
    pub solicitations: Solicitations,
    /// The 225 outbound budget.
    pub budget: OutboundBudget,
}

/// Drive the profile-sync ingest: decode each inbound frame and dispatch 223/224/225.
///
/// Wired exactly like the holdings (`peer.rs`) and store-melt ingests: one `broadcast::Receiver`
/// over `(PeerId, Message)`, a `Lagged` that logs and continues (a missed announce is re-heard from
/// any holder), a `Closed` that returns, and every per-frame body inside
/// [`catch_iteration`](crate::shared::catch_iteration) so one panic cannot kill the subsystem for
/// the process's lifetime.
pub async fn run_profile_sync_ingest(
    mut inbound: tokio::sync::broadcast::Receiver<(PeerId, dig_gossip::DigMessage)>,
    ctx: ProfileSyncContext,
) {
    use dig_gossip::service::profile_sync::{
        profile_body_payload, profile_body_request_payload, profile_root_announce_payload,
    };
    loop {
        let (sender, msg) = match inbound.recv().await {
            Ok(pair) => pair,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::debug!(
                    skipped,
                    "profile-sync ingest lagged; a missed announce is re-heard from any holder"
                );
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        if let Some(announce) = profile_root_announce_payload(&msg) {
            let ctx = ctx.clone();
            let _ = crate::shared::catch_iteration("profile_root_announce", async move {
                handle_root_announce(
                    &ctx.store,
                    &*ctx.subs,
                    &*ctx.resolver,
                    &*ctx.transport,
                    &ctx.solicitations,
                    &announce,
                )
                .await;
            })
            .await;
        } else if let Some(request) = profile_body_request_payload(&msg) {
            let ctx = ctx.clone();
            let _ = crate::shared::catch_iteration("profile_body_request", async move {
                serve_body_request(&ctx.store, &*ctx.transport, &ctx.budget, sender, &request).await;
            })
            .await;
        } else if let Some(body) = profile_body_payload(&msg) {
            let ctx = ctx.clone();
            let _ = crate::shared::catch_iteration("profile_body", async move {
                let outcome = accept_body(
                    &ctx.store,
                    &*ctx.subs,
                    &ctx.solicitations,
                    &*ctx.transport,
                    &*ctx.penalty,
                    sender,
                    &body,
                )
                .await;
                if let AcceptOutcome::Accepted { bytes, announced } = outcome {
                    tracing::info!(
                        store = %body.store_id.to_string(),
                        root = %body.root.to_string(),
                        bytes,
                        announced,
                        "profile-sync: chain-anchored body accepted and re-announced"
                    );
                }
            })
            .await;
        }
    }
}

/// Build the outbound 223 frame for `(store_id, root)` — exposed so the caller that publishes this
/// node's OWN profile uses the same builder the accept path does.
#[must_use]
pub fn announce_frame(store_id: [u8; 32], root: [u8; 32]) -> dig_gossip::DigMessage {
    frame_profile_root_announce(&ProfileRootRef {
        store_id: Bytes32::from(store_id),
        root: Bytes32::from(root),
    })
}

/// Build the outbound 224 frame for `(store_id, root)`.
#[must_use]
pub fn request_frame(store_id: [u8; 32], root: [u8; 32]) -> dig_gossip::DigMessage {
    frame_profile_body_request(&ProfileRootRef {
        store_id: Bytes32::from(store_id),
        root: Bytes32::from(root),
    })
}
