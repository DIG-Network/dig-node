//! The reshare leg — a node that READ content becomes a discoverable HOLDER of the whole capsule
//! (#1576). This is the step that closes the MVP content-replication flywheel.
//!
//! ```text
//!   install -> connect -> discover -> read -> CACHE THE WHOLE CAPSULE -> ANNOUNCE AS HOLDER
//!                            ^                                                    |
//!                            +----------------------------------------------------+
//! ```
//!
//! A resource read fetches only the bytes asked for. That makes the reader faster but the NETWORK no
//! stronger: it still cannot serve anything, because a `.dig` is served whole (every retrieval key,
//! with proofs). So after a read completes, this module pulls the ENTIRE `.dig` module for that
//! generation, and only then does the node become a holder — which is what makes each read leave the
//! content MORE available than it found it.
//!
//! # The promotion ladder (why the artifact lands in three places, not one)
//!
//! ```text
//!   <downloads>/modules/<store>-<root>.dig.download.tmp   staging (dig-download FileSink)
//!   <downloads>/modules/<store>-<root>.dig                verified, NOT yet a holder
//!   <cache>/modules/<store>/<root>.dig                    CACHED  ==  ANNOUNCED AS HOLDER
//! ```
//!
//! The last hop is the one that matters. The node's DHT provider records are derived from its CACHE
//! INVENTORY (`refresh_inventory`, #1586), so the moment a module file appears at the cache path this
//! node is advertising itself, network-wide, as an authoritative source of that capsule. Everything
//! here is arranged so that hop happens ONLY for a pull that fully succeeded:
//!
//! 1. The pull stages OUTSIDE the cache, so a partial or failed pull is not even a candidate for
//!    announcement — there is no window in which a half-pulled capsule sits at the cache path.
//! 2. The move happens only on `download()` returning `Ok` — never on "finalize observed", never on
//!    partial staging, never after an `Err`. `Ok` is the ONLY signal that both of the engine's
//!    fail-closed gates passed.
//! 3. Even `Ok` is not taken on faith. Before the move, the artifact on disk is re-hashed and compared
//!    against the digest the anchor verifier recorded for the bytes it actually ADMITTED
//!    ([`ChainAnchoredModuleVerifier::admitted_digest`]). Both sides of that comparison are this node's
//!    own — no peer supplies either. It is what catches, from outside the engine, a promoted artifact
//!    that is not the verified one.
//!
//! # The pull is a BACKGROUND warm — it must never slow the read
//!
//! The read leg's latency is user-facing, and a whole-capsule pull is orders of magnitude larger than
//! the resource that triggered it. So [`spawn_capsule_warm`] returns immediately and the pull runs on
//! its own task; a read never awaits it, and a failed warm never fails the read that triggered it. One
//! warm per generation at a time ([`WarmRegistry`]), so a burst of reads across a capsule's resources
//! cannot start N concurrent pulls of the same module.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use digstore_core::Bytes32;

use crate::capsule_key::CapsuleKey;

use super::module_anchor::{sha256, ChainAnchoredModuleVerifier};

/// The default cap on DISTINCT generations [`WarmRegistry`] admits at once.
///
/// The per-generation dedup below stops a burst of reads across ONE capsule from starting N concurrent
/// pulls of it, but says nothing about breadth: reads across K DISTINCT capsules start K concurrent
/// pulls, each able to assemble up to a whole `.dig` module in memory/disk at once (#1615/G3). This cap
/// bounds that — reachable from ordinary read breadth, no attacker required.
pub(crate) const DEFAULT_MAX_CONCURRENT_WARMS: usize = 4;

/// The set of `(store, root)` generations a warm pull is currently in flight for, bounded to at most
/// [`Self::max_concurrent`] distinct generations at once.
///
/// A capsule read typically fetches several resources in quick succession, each of which would
/// otherwise trigger its own whole-module pull of the SAME module — N concurrent pulls of one capsule,
/// racing each other into the same staging file. This registry makes the warm idempotent while it runs,
/// AND caps how many DIFFERENT generations may warm concurrently.
#[derive(Debug)]
pub struct WarmRegistry {
    in_flight: Mutex<HashSet<String>>,
    max_concurrent: usize,
}

impl Default for WarmRegistry {
    fn default() -> Self {
        WarmRegistry::with_limit(DEFAULT_MAX_CONCURRENT_WARMS)
    }
}

impl WarmRegistry {
    /// An empty registry, capped at [`DEFAULT_MAX_CONCURRENT_WARMS`] concurrent generations.
    pub fn new() -> Self {
        WarmRegistry::default()
    }

    /// An empty registry capped at `max_concurrent` distinct generations warming at once.
    pub fn with_limit(max_concurrent: usize) -> Self {
        WarmRegistry {
            in_flight: Mutex::new(HashSet::new()),
            max_concurrent,
        }
    }

    /// Claim `key` for a warm pull.
    ///
    /// Refuses (`None`) in two cases: a warm for `key` is already in flight, or the registry is already
    /// at its concurrency cap for OTHER generations. The cap SKIPS rather than queues — a warm is a
    /// best-effort background nicety, and queueing it would only defer holding the same memory a bit
    /// later; the next read of that capsule will simply try again.
    ///
    /// The claim is released when the returned guard drops — including on panic, so a panicking pull
    /// cannot permanently block a generation from ever being warmed again.
    pub(crate) fn claim(self: &Arc<Self>, key: String) -> Option<WarmClaim> {
        let mut guard = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.contains(&key) {
            return None;
        }
        if guard.len() >= self.max_concurrent {
            tracing::debug!(
                generation = %key,
                max_concurrent = self.max_concurrent,
                "capsule warm skipped: at the concurrent-warm cap"
            );
            return None;
        }
        guard.insert(key.clone());
        Some(WarmClaim {
            registry: Arc::clone(self),
            key,
        })
    }

    /// The generations currently warming, as the [`CapsuleIdentity`] values
    /// [`dig_sex::acquisition::decide`] reasons over.
    ///
    /// Materialising the set is cheap by construction: it is bounded by
    /// [`Self::max_concurrent`] (4 by default), which is the same bound that stops an unbounded
    /// number of concurrent pulls. A key that does not parse as `store:root` cannot have been
    /// written by [`Self::claim`] and is skipped rather than guessed at — omitting it can only make
    /// the decision say "acquire" for something already in flight, which the atomic `claim` below
    /// then refuses, so the two answers can never disagree in the unsafe direction.
    pub(crate) fn in_flight_capsules(&self) -> HashSet<dig_sex::CapsuleIdentity> {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(|key| {
                let (store, root) = key.split_once(':')?;
                Some(CapsuleKey::parse(store, root)?.identity())
            })
            .collect()
    }

    /// Whether a warm is currently in flight for `key` (diagnostics + tests).
    pub fn is_warming(&self, key: &str) -> bool {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(key)
    }
}

/// Releases a [`WarmRegistry`] claim on drop.
///
/// `pub(crate)` so the §21 backfill leg ([`crate::Node::maybe_backfill_capsule`]) can hold a claim on
/// the SAME shared gate as the reshare warm (#1614) — the guard whose drop frees the single-flight slot.
pub(crate) struct WarmClaim {
    registry: Arc<WarmRegistry>,
    key: String,
}

impl Drop for WarmClaim {
    fn drop(&mut self) {
        self.registry
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.key);
    }
}

/// Why a capsule warm did not end with this node holding + announcing the capsule.
///
/// Every variant is a REFUSAL to become a holder. None of them carries peer-supplied text (#1603): the
/// wording is this node's own, and any id in a log line goes through the serve log's sentinel.
#[derive(Debug, PartialEq, Eq)]
pub enum WarmFailure {
    /// The chain could not tell us the generation's anchored root, so there was nothing to verify
    /// against. Fail-closed: without a chain anchor the pull has no root of trust at all.
    NoChainAnchor,
    /// The pull itself failed (no holders, holders exhausted, or a fail-closed gate rejected the
    /// assembled module).
    ///
    /// The `reason` is dig-download's own error text, carried in the VALUE rather than only written
    /// to a log. A reason that exists only in a log is exactly what failed here: the shipped
    /// `let...else` could not bind the `Err`, four live diagnostic rounds produced no cause at all
    /// (dig_ecosystem#3128), and a test asserting on the log alone is hostage to whichever subscriber
    /// happened to observe the callsite first. dig-download composes the text from this node's own
    /// vocabulary plus SENTINELLED peer ids, so carrying it cannot let a peer author what this node
    /// records (#1603).
    PullFailed {
        /// dig-download's terminal error for this pull, as an operator would read it.
        reason: String,
    },
    /// `download()` returned `Ok`, but the artifact on disk is NOT the one the anchor verifier admitted.
    /// The capsule is discarded and NOT announced.
    PromotedArtifactMismatch,
    /// The verified artifact could not be moved into the cache (an I/O failure), so this node does not
    /// hold it and must not claim to.
    CacheWriteFailed,
}

/// The outcome of a capsule warm.
#[derive(Debug, PartialEq, Eq)]
pub enum WarmOutcome {
    /// The whole capsule is verified, cached, and this node is now announced as a holder of it.
    Held {
        /// The verified module length in bytes.
        bytes: u64,
    },
    /// The node did NOT become a holder. See [`WarmFailure`].
    Refused(WarmFailure),
    /// A warm for this generation was already in flight, OR the registry was already at its
    /// concurrent-warm cap for other generations (see [`WarmRegistry`]) — either way, this call did
    /// nothing and started no pull.
    AlreadyWarming,
    /// This node already holds the capsule (the cache path exists) — nothing to pull, nothing to
    /// announce again.
    AlreadyHeld,
}

/// Whether a completed warm makes this node a DISCOVERABLE holder of what it just pulled.
///
/// The two callers of a warm want opposite answers, and the difference is a security boundary rather
/// than a preference (dig-node#276):
///
/// * A warm this node's OWN operator provoked — a local read — SHOULD announce. That is the reshare
///   flywheel: every read leaves the content more available than it found it.
/// * A warm a STRANGER provoked, by asking this node to relay a capsule it does not hold, MUST NOT.
///   Announcing it would let any peer drive this node into advertising capsules of the ATTACKER's
///   choosing — a few hundred request bytes in, an attacker-shaped holder inventory out, and eviction
///   pressure on the operator's own content. That is precisely the hole
///   [`crate::download::NodeContent`]'s `origin != Local` reshare refusal exists to close, and
///   relaying reopens it one level up unless the announce is suppressed here.
///
/// An enum rather than a `bool` so the call site names which of the two it is, and so a future third
/// caller has to CHOOSE rather than inherit whichever default was in the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderClaim {
    /// Announce the capsule: this node pulled it for ITSELF and is a genuine, willing holder.
    Announce,
    /// Cache the capsule but announce NOTHING: this node pulled it on a stranger's behalf and is a
    /// relay, not a holder.
    Suppress,
}

/// Where a capsule warm stages + promotes to, and how it announces.
///
/// A struct rather than a long argument list so the call site reads as one intention, and so the
/// announce hook is an explicit injected dependency — a warm that could reach into a global to announce
/// would be a warm whose announce could not be tested for absence.
pub struct WarmPaths {
    /// The directory the pull stages into. MUST NOT be inside the cache: a file under the cache path is
    /// already an announcement (see the module docs).
    pub staging_dir: PathBuf,
    /// The node's cache dir. The final hop writes `<cache>/modules/<store>/<root>.dig`.
    pub cache_dir: PathBuf,
}

impl WarmPaths {
    /// The staging target for a capsule — the path dig-download's `FileSink` finalizes onto, having
    /// staged in `<that>.download.tmp`.
    fn staged_module(&self, capsule: &CapsuleKey) -> PathBuf {
        capsule.staged_module_path(&self.staging_dir)
    }

    /// The cache path whose EXISTENCE makes this node a holder.
    fn cached_module(&self, capsule: &CapsuleKey) -> PathBuf {
        capsule.module_path(&self.cache_dir)
    }
}

/// Promote a verified capsule into the cache — the hop that makes this node a holder — having PROVEN
/// the artifact on disk is the one the anchor verifier admitted.
///
/// Returns the promoted byte length. This is deliberately the only function in the crate that writes a
/// module into the cache on the reshare path, so the re-check below cannot be bypassed by a second
/// promotion route.
fn promote_into_cache(
    staged: &Path,
    cached: &Path,
    verifier: &ChainAnchoredModuleVerifier,
    claim: HolderClaim,
) -> Result<u64, WarmFailure> {
    // Obligation: do NOT trust `download() == Ok` alone. Re-hash the artifact that actually exists on
    // disk and compare it against the digest of the bytes the anchor gate ADMITTED. A mismatch means the
    // verified artifact and the promoted artifact are different objects — the promotion is abandoned
    // rather than "repaired", because there is no way to tell which of the two is the real one.
    let bytes = std::fs::read(staged).map_err(|_| WarmFailure::PromotedArtifactMismatch)?;
    let Some(admitted) = verifier.admitted_digest() else {
        // The gate never admitted anything, yet a staged artifact exists. Refuse: promoting here would
        // be promoting an artifact no gate ever saw.
        return Err(WarmFailure::PromotedArtifactMismatch);
    };
    if sha256(&bytes) != admitted {
        return Err(WarmFailure::PromotedArtifactMismatch);
    }

    if let Some(parent) = cached.parent() {
        std::fs::create_dir_all(parent).map_err(|_| WarmFailure::CacheWriteFailed)?;
    }
    // Write-then-rename INTO the cache, so a reader never observes a partial module at the cache path
    // (whose mere existence is this node's holder claim).
    let tmp = cached.with_extension("dig.warm.tmp");
    std::fs::write(&tmp, &bytes).map_err(|_| WarmFailure::CacheWriteFailed)?;
    // The holder claim is persisted BEFORE the capsule becomes visible at the cache path, because the
    // cache path is the inventory (dig-node#276). Between the rename and a later marker write there
    // would be a window in which an unrelated reconcile — a chain-watch gap-fill, a peer-presence
    // re-announce, a restart — reads the capsule with no marker beside it and advertises this node as a
    // holder of a stranger's content. Writing first closes the window; the marker names a `<root>.relay`
    // sidecar, which the inventory scan never mistakes for a capsule.
    persist_holder_claim(cached, claim)?;
    std::fs::rename(&tmp, cached).map_err(|_| {
        let _ = std::fs::remove_file(&tmp);
        WarmFailure::CacheWriteFailed
    })?;
    // #1991 telemetry: this is the reshare-warm capsule land — a whole-capsule NETWORK pull that
    // just wrote into the cache, exactly the same kind of event `Node::sync_module_from` counts for
    // the on-demand/gap-fill/fetch-side-backfill paths. This promotion is a SEPARATE write-then-rename
    // (never routes through `sync_module_from`), so it needs its own increment to make `refetch_count`
    // complete over every landing path; the two sites are mutually exclusive, so a land is never
    // double-counted.
    crate::CACHE_REFETCH_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(bytes.len() as u64)
}

/// Record `claim` durably beside the capsule about to appear at `cached`.
///
/// [`HolderClaim::Suppress`] writes the `<root>.relay` sidecar; [`HolderClaim::Announce`] REMOVES any
/// sidecar already there. The removal is not defensive tidying — it is how a generation this node
/// previously relayed becomes genuinely held when the node later pulls it for itself, so a relay never
/// permanently disqualifies a capsule from the flywheel.
///
/// A marker that cannot be written is a hard [`WarmFailure::CacheWriteFailed`], never a warning: a
/// relayed capsule promoted without its marker is exactly the advertised-stranger-content state this
/// mechanism exists to prevent, so the promotion is abandoned instead.
pub(crate) fn persist_holder_claim(cached: &Path, claim: HolderClaim) -> Result<(), WarmFailure> {
    let Some(marker) = crate::capsule_key::relay_marker_beside(cached) else {
        return Err(WarmFailure::CacheWriteFailed);
    };
    match claim {
        HolderClaim::Suppress => {
            std::fs::write(&marker, RELAY_MARKER_BODY).map_err(|_| WarmFailure::CacheWriteFailed)
        }
        HolderClaim::Announce => match std::fs::remove_file(&marker) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(WarmFailure::CacheWriteFailed),
        },
    }
}

/// What a relay marker contains. The marker's EXISTENCE is the whole signal, so the body is for a human
/// reading a cache directory and nothing parses it.
const RELAY_MARKER_BODY: &[u8] =
    b"relayed: held on another node's behalf; this node is not a holder (dig-node#276)
";

/// How often [`CapsuleWarmer::await_landing`] re-checks the cache while its grace runs. Short enough
/// that a capsule landing early is served promptly, long enough that the wait is not a spin.
const LANDING_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// A discarded pull's whole on-disk footprint, so the two halves cannot be erased separately.
///
/// A partial capsule is stored as TWO facts in two places — the staged bytes under the staging dir,
/// and the resume checkpoint in the [`StateStore`](dig_download::StateStore) — and they are only ever
/// true together. Passing them as one value is what stops a caller erasing one and leaving the other,
/// which is precisely the state dig-node#332 measured: a checkpoint claiming chunks that no longer
/// existed on disk.
struct StagedPull<'a> {
    /// The path dig-download's `FileSink` finalizes onto (its in-progress bytes live beside it, at
    /// [`staging_path_for`](dig_download::staging_path_for)).
    staged: &'a Path,
    /// Where the resume checkpoint lives.
    state_store: &'a dyn dig_download::StateStore,
    /// The checkpoint's key — dig-download's own, never a second derivation of it.
    key: String,
}

impl<'a> StagedPull<'a> {
    /// Name the pull of `(store_hex, root_hex)` staging at `staged`.
    fn new(
        staged: &'a Path,
        state_store: &'a dyn dig_download::StateStore,
        store_hex: &str,
        root_hex: &str,
    ) -> Self {
        StagedPull {
            staged,
            state_store,
            key: dig_download::module_download_key(store_hex, root_hex),
        }
    }

    /// Erase a warm's staging artifacts — bytes AND checkpoint — so a failed pull leaves nothing
    /// behind that a later run (or a GC sweep) could mistake for progress.
    ///
    /// # Why the checkpoint goes with the bytes
    ///
    /// A surviving checkpoint describes chunks that are no longer on disk, so the next warm resumes
    /// against them, fails to read them back, and re-attributes each one. That is harmless to
    /// correctness — the re-attribution re-fetches — but it emits the per-chunk warning an operator
    /// reads as *a peer served me bytes that did not match*, i.e. an attack indicator, on a routine
    /// discard. A monitoring signal that fires on a benign path is worse than none, because the real
    /// event stops being distinguishable from the noise (dig-node#332).
    ///
    /// Every step is best-effort: this runs on a path that is ALREADY failing, and a cleanup error
    /// must not replace the failure the caller has to report.
    async fn erase(&self) {
        let _ = std::fs::remove_file(self.staged);
        let _ = std::fs::remove_file(dig_download::staging_path_for(self.staged));
        let _ = self.state_store.clear(&self.key).await;
    }
}

/// What a FAILED pull leaves behind in the staging area.
///
/// A partially-staged capsule is either *the bytes so far* or *evidence of a lie*, and the two demand
/// opposite treatment. Discarding both is what dig-node#328 measured in the field: a 135 MB capsule cut
/// at 34.6 MB re-downloaded 182 MB on the retry — 0.02% MORE than fetching it from scratch — because the
/// only thing that survived the failure was the resume checkpoint, never the bytes it described. Keeping
/// both would be the opposite defect: a hostile hop's bytes surviving on disk for a later honest range to
/// complete around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagingDisposition {
    /// The staged bytes are still the best evidence available, so the next warm resumes from them.
    ///
    /// Safe for EVERY non-verification failure because dig-download re-attributes each staged chunk
    /// against the descriptor's `chunk_hashes` before adopting it on resume (`read_back_verified_chunk`)
    /// and re-fetches anything that fails — so preserving bytes can cost a re-fetch, never a wrong
    /// artifact.
    Preserve,
    /// The staged bytes are attributable only to a source that has been PROVEN false, so they are
    /// erased rather than left for a later pull to resume around.
    Discard,
}

impl StagingDisposition {
    /// What to do with `staged` after a pull failed with `error`.
    ///
    /// Deliberately an EXHAUSTIVE match with no `_` arm: `dig_download::DownloadError` is not
    /// `#[non_exhaustive]`, so a new failure mode upstream breaks this build and forces the
    /// keep-or-erase question to be answered, instead of defaulting silently to whichever branch a
    /// wildcard happened to name. That is the whole point of naming the disposition as a type — the
    /// only place the choice can be made is here, once, per error kind.
    fn for_failure(error: &dig_download::DownloadError) -> Self {
        use dig_download::DownloadError as E;
        match error {
            // VERIFICATION failed. The staged bytes verified against a descriptor the final gates then
            // proved false (a whole-blob `module_hash` mismatch, or a blob the chain does not anchor),
            // so every one of them is a hostile hop's authorship. NC-12: a hop's bytes may be garbage,
            // and garbage that survives on disk is garbage a later honest range completes around.
            E::Verify(_) => StagingDisposition::Discard,

            // TRANSPORT failed, in one of its several shapes: the link dropped, the source stalled, the
            // holder set was exhausted mid-capsule, discovery or the metadata probe came back empty, or
            // a holder's paged prologue ended short. In every one of these the bytes already staged are
            // bytes that MATCHED the descriptor's per-chunk hash before being written, and no gate has
            // contradicted them. They are exactly what a resume exists to reuse.
            E::Transport { .. }
            | E::Timeout { .. }
            | E::NoProviders { .. }
            | E::NotFound { .. }
            | E::MetadataProbeFailed { .. }
            | E::PagedPrologueUnsupported { .. }
            | E::Cancelled => StagingDisposition::Preserve,

            // LOCAL failures — this node's disk, its state store, a malformed request, or an
            // orchestrator that ended without a verdict. Nothing here impeaches the bytes; a disk that
            // failed mid-write leaves the chunk uncheckpointed, so the resume re-fetches it anyway.
            E::State(_) | E::Sink(_) | E::NotDownloadable | E::TaskEnded => {
                StagingDisposition::Preserve
            }
        }
    }

    /// Apply this disposition to `pull`.
    ///
    /// [`Preserve`](Self::Preserve) touches NOTHING — not the bytes and not the checkpoint. The two
    /// are what a resume is made of, and dropping either half is what made the resume machinery
    /// structurally unreachable in the field (dig-node#328).
    async fn apply(self, pull: &StagedPull<'_>) {
        match self {
            StagingDisposition::Preserve => {}
            StagingDisposition::Discard => pull.erase().await,
        }
    }
}

/// Reports the end of a pull when it goes out of scope, so the boundary is reported on EVERY exit —
/// including an unwinding panic.
///
/// # Why a guard and not a statement after the `await`
///
/// A plain call after `downloader.download(...).await` is skipped when that await PANICS, and a
/// panic here is reachable rather than theoretical: the tier-0 precache path runs
/// `run_round -> fetch_and_cache -> warm_capped -> download` inside a real
/// [`catch_unwind`](crate::shared::panic_guard) added precisely so a panic there is survived, and this
/// crate does not build with `panic = "abort"`. So the task continues and the ledger entry leaks.
///
/// The leak is not a tidiness matter — it restores the two defects this budget exists to remove: the
/// capsule becomes permanently ineligible for the relay path, and the resulting exhaustion is composed
/// into a transport error NAMING A PEER, which `SPEC.md` §21.1 forbids in as many words.
///
/// `Drop` runs during unwinding, so the guard reports on the panic path and the returning paths
/// through one mechanism. That is the same lesson this file has already paid for twice: prefer making
/// the omission unexpressible over asserting that it does not occur.
struct PullBoundary<'a> {
    /// Told the pull is over. Borrowed, so the guard cannot outlive the warmer driving the pull.
    lifecycle: &'a dyn super::PullLifecycle,
    /// The capsule whose pull this is.
    store_hex: &'a str,
    root_hex: &'a str,
}

impl<'a> PullBoundary<'a> {
    /// Open the boundary. It closes when the value drops.
    fn new(lifecycle: &'a dyn super::PullLifecycle, store_hex: &'a str, root_hex: &'a str) -> Self {
        PullBoundary {
            lifecycle,
            store_hex,
            root_hex,
        }
    }
}

impl Drop for PullBoundary<'_> {
    fn drop(&mut self) {
        self.lifecycle.pull_finished(self.store_hex, self.root_hex);
    }
}

/// Everything a capsule warm needs, resolved once at composition time.
///
/// `anchor_resolver` is what makes the whole reshare path trustworthy: the generation root the pull is
/// verified against is resolved through it (the CHAIN), never taken from the peer that serves the
/// module.
pub struct CapsuleWarmer {
    /// Locates the capsule's holders.
    locator: Arc<dyn dig_download::ProviderLocator>,
    /// Talks `dig.getModuleInfo` / `dig.fetchModuleRange` to them.
    transport: Arc<dyn dig_download::ModuleTransport>,
    /// Told when each pull ends, so the transport can release state scoped to that pull.
    ///
    /// Usually the SAME object as `transport`, handed over twice under its two roles. It is a
    /// separate field because the pull boundary is this warmer's knowledge and the state is the
    /// transport's, and neither can see the other's half.
    pull_lifecycle: Arc<dyn super::PullLifecycle>,
    /// Resume checkpoints, so an interrupted warm does not restart from zero.
    state_store: Arc<dyn dig_download::StateStore>,
    /// The CHAIN's view of each store's anchored root — the pull's only root of trust.
    anchor_resolver: Arc<dyn crate::shared::AnchoredRootResolver>,
    /// Where to stage + promote.
    paths: WarmPaths,
    /// Called after a capsule is cached, to reconcile this node's DHT provider records with its new
    /// inventory (this is the ANNOUNCE). Invoked ONLY on a fully-successful warm.
    announce: Arc<dyn AnnounceHolder>,
    /// One warm per generation at a time.
    registry: Arc<WarmRegistry>,
    /// Tunables for the pull.
    config: dig_download::ModuleDownloadConfig,
    /// The tier-aware `<cache>/modules` size-cap sweep, run after a SUCCESSFUL reshare-warm land so this
    /// read-triggered whole-capsule pull cannot grow the modules cache past [`cache_cap_bytes`] (#2053).
    /// The SAME seam the tier-0 precache loop uses ([`crate::tier0_live::ModulesCacheEvictor`]), so both
    /// on-demand land paths bound the cache through one implementation rather than two driftable ones.
    evictor: Arc<dyn crate::tier0_live::ModulesCacheEvictor>,
}

/// Announces this node's inventory to the DHT — the step that makes a cached capsule DISCOVERABLE.
///
/// A trait rather than a closure so a test can assert an announce did NOT happen: "no announce on a
/// failed pull" is a property that needs a spy, and a property that cannot be observed cannot be
/// defended.
#[async_trait::async_trait]
pub trait AnnounceHolder: Send + Sync {
    /// Reconcile the DHT provider records with the node's current cache inventory.
    async fn announce_inventory(&self);
}

impl CapsuleWarmer {
    /// Assemble a warmer from its injected seams.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        locator: Arc<dyn dig_download::ProviderLocator>,
        transport: Arc<dyn dig_download::ModuleTransport>,
        pull_lifecycle: Arc<dyn super::PullLifecycle>,
        state_store: Arc<dyn dig_download::StateStore>,
        anchor_resolver: Arc<dyn crate::shared::AnchoredRootResolver>,
        paths: WarmPaths,
        announce: Arc<dyn AnnounceHolder>,
        registry: Arc<WarmRegistry>,
        config: dig_download::ModuleDownloadConfig,
        evictor: Arc<dyn crate::tier0_live::ModulesCacheEvictor>,
    ) -> Arc<Self> {
        Arc::new(CapsuleWarmer {
            locator,
            transport,
            pull_lifecycle,
            state_store,
            anchor_resolver,
            paths,
            announce,
            registry,
            config,
            evictor,
        })
    }

    /// The single-flight [`WarmRegistry`] this warmer claims against. Exposed so a test can prove the
    /// reshare leg and the §21 backfill leg were wired to the SAME shared gate (#1614).
    #[cfg(test)]
    pub(crate) fn registry(&self) -> &Arc<WarmRegistry> {
        &self.registry
    }

    /// Pull the whole capsule for `(store_hex, root_hex)`, cache it, and announce this node as a
    /// holder — the full reshare step, awaited.
    ///
    /// Callers on the read path use [`spawn_capsule_warm`] instead; this is the awaitable core so the
    /// behaviour is testable without a background task.
    pub async fn warm(self: &Arc<Self>, store_hex: &str, root_hex: &str) -> WarmOutcome {
        self.warm_claiming(store_hex, root_hex, HolderClaim::Announce)
            .await
    }

    /// Whether this node can serve `(store_hex, root_hex)` from its cache RIGHT NOW.
    ///
    /// The cache path's existence IS the answer everywhere else in this module (it is what a holder
    /// claim is made of), so this asks the same question the same way rather than adding a second,
    /// driftable notion of "landed".
    pub(crate) fn holds(&self, store_hex: &str, root_hex: &str) -> bool {
        CapsuleKey::parse(store_hex, root_hex)
            .is_some_and(|capsule| self.paths.cached_module(&capsule).exists())
    }

    /// How many bytes of `(store_hex, root_hex)` are staged on disk — this node's own honest
    /// measure of how far an in-flight pull has got.
    ///
    /// Zero for a pull that has not started, has staged nothing yet, or names a non-canonical
    /// generation. It is a LIVENESS signal for a waiting requestor and nothing else: it says how far
    /// this hop has got, never that any byte is correct — that is settled by the merkle verification
    /// every one of these bytes must still pass (NC-12).
    pub(crate) fn staged_bytes(&self, store_hex: &str, root_hex: &str) -> u64 {
        let Some(capsule) = CapsuleKey::parse(store_hex, root_hex) else {
            return 0;
        };
        let staged = self.paths.staged_module(&capsule);
        let in_progress = dig_download::staging_path_for(&staged);
        // The in-progress file is where a running pull writes; the finalized one appears only at the
        // very end. Whichever exists is the pull's current extent.
        [in_progress, staged]
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .max()
            .unwrap_or(0)
    }

    /// Wait up to `grace` for a background pull of `(store_hex, root_hex)` to reach the cache,
    /// reporting whether it did.
    ///
    /// # Why a grace at all, rather than answering immediately
    ///
    /// A capsule small enough to land inside the grace is answered by the hop in ONE round trip,
    /// exactly as it was before dig-node#333 — so the case that already worked keeps working and no
    /// requestor pays a poll interval for it. The grace is deliberately far inside the requestor's
    /// own descriptor rungs; what it must never do is stretch to cover a bulk transfer, which is the
    /// held-slot cost the rungs exist to bound.
    pub(crate) async fn await_landing(
        &self,
        store_hex: &str,
        root_hex: &str,
        grace: std::time::Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            if self.holds(store_hex, root_hex) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(LANDING_POLL_INTERVAL.min(grace)).await;
        }
    }

    /// [`warm`](Self::warm) for a capsule pulled on ANOTHER node's behalf (dig-node#276): identical in
    /// every trust step — chain anchor, merkle verification, promote-recheck, cache bound — except that
    /// this node does **not** announce itself as a holder of the result.
    ///
    /// The capsule still lands in the cache, because that is what lets the relayed module windows be
    /// served from the same code path a genuine holder serves from, byte-identically. What it does not
    /// do is make a stranger's choice of content into this node's advertised inventory.
    ///
    /// # This competes with local warms for the same slots
    ///
    /// The pull runs under the SHARED [`WarmRegistry`], which admits
    /// [`DEFAULT_MAX_CONCURRENT_WARMS`] generations across this whole node — relayed and local alike.
    /// So a relay started for a stranger occupies a slot this node's own reads would otherwise use,
    /// and since dig-node#333 the pull is SPAWNED rather than awaited, meaning it keeps that slot even
    /// after the requestor that asked for it has given up and disconnected.
    ///
    /// That is bounded and deliberate rather than a hole — the cap is global, the leg is opt-in
    /// (`DIG_NODE_ONION_RELAY`, default OFF), and the requestor must additionally be inside its
    /// proxy-class allowance — but it IS a real cost of enabling the relay, and an operator who
    /// enables it should know that a peer which abandons its request can still hold a warm slot until
    /// the pull finishes or fails.
    pub async fn warm_relayed(self: &Arc<Self>, store_hex: &str, root_hex: &str) -> WarmOutcome {
        self.warm_claiming(store_hex, root_hex, HolderClaim::Suppress)
            .await
    }

    /// The shared body of [`warm`](Self::warm) and [`warm_relayed`](Self::warm_relayed).
    async fn warm_claiming(
        self: &Arc<Self>,
        store_hex: &str,
        root_hex: &str,
        claim: HolderClaim,
    ) -> WarmOutcome {
        let outcome = self
            .warm_with_config(store_hex, root_hex, self.config.clone(), claim)
            .await;
        // #2053: the tier-aware `<cache>/modules` size-cap sweep, run ONLY after a land that actually
        // grew the cache (`Held`) — a refusal wrote nothing, so there is nothing new to bound. This
        // closes the last on-demand land path left unbounded: like the read-path §21 sync (#2041) and
        // the tier-0 precache loop (#1934), a reshare-warm promotion must ITSELF bound the cache so the
        // `<cache>/modules` cap holds independent of any background loop's state.
        //
        // Lock context (the load-bearing choice): a reshare warm holds NO `cache_lock` — the warmer is a
        // standalone seam with no Node handle or guard across the land — so this drives the ASYNC
        // [`crate::Node::evict_modules_if_needed`] (which takes `cache_lock` fresh), NEVER the locked
        // core. Calling the locked core here would evict without serialization; calling the async
        // variant while holding the lock would deadlock — neither applies because no lock is held.
        if matches!(outcome, WarmOutcome::Held { .. }) {
            self.evictor.evict_if_needed().await;
        }
        outcome
    }

    /// [`warm`](Self::warm) with a HARD per-pull byte ceiling — the tier-0 eager-precache entry point
    /// (epic #1934, PR-3). `max_bytes` lowers the pull's [`ModuleDownloadConfig::max_module_size`] so a
    /// store whose descriptor declares (or whose true assembled size reaches) more than the caller's
    /// remaining tier-0 sub-budget is REFUSED before it is allocated, chunked, or cached — the
    /// provider-reported `size_bytes` hint is never trusted as an allocation size, only this true ceiling
    /// governs. The chain-anchor gate, merkle verification, promote-recheck, and announce are identical
    /// to [`warm`](Self::warm); only the size ceiling tightens.
    pub async fn warm_capped(
        self: &Arc<Self>,
        store_hex: &str,
        root_hex: &str,
        max_bytes: u64,
    ) -> WarmOutcome {
        let mut config = self.config.clone();
        // The ceiling is the TIGHTER of the node-wide default and the caller's per-pull budget, so a
        // tier-0 round can never pull more than its remaining sub-budget even if the node default is
        // larger.
        config.max_module_size = config.max_module_size.min(max_bytes);
        self.warm_with_config(store_hex, root_hex, config, HolderClaim::Announce)
            .await
    }

    /// The awaitable core of [`warm`](Self::warm) / [`warm_capped`](Self::warm_capped), parameterized by
    /// the pull `config` so the byte ceiling can vary per call while every trust step stays identical.
    async fn warm_with_config(
        self: &Arc<Self>,
        store_hex: &str,
        root_hex: &str,
        config: dig_download::ModuleDownloadConfig,
        claim: HolderClaim,
    ) -> WarmOutcome {
        // Already a holder → nothing to pull, nothing to announce again. Checked BEFORE claiming a
        // registry slot: a burst of reads across an already-cached capsule should cost one stat call
        // each, never a wasted concurrency slot another generation could have used.
        // The ids arrive from the read path, so they are validated into a `CapsuleKey` BEFORE any
        // staging or cache path is built from them (#1599). A non-canonical key names no generation the
        // chain could anchor, so the pull is refused outright rather than attempted.
        let Some(capsule) = CapsuleKey::parse(store_hex, root_hex) else {
            return WarmOutcome::Refused(WarmFailure::NoChainAnchor);
        };
        let cached_path = self.paths.cached_module(&capsule);
        if cached_path.exists() {
            // Already on disk — but possibly as a RELAYED capsule, suppressed from the inventory. A warm
            // this node drives for ITSELF is the event that promotes it to a genuine holding, so clear
            // the marker and announce the newly-announceable capsule. Without this a generation relayed
            // once could never enter the flywheel, however often the node later read it for itself.
            let was_relayed = crate::capsule_key::relay_marker_beside(&cached_path)
                .is_some_and(|marker| marker.exists());
            if claim == HolderClaim::Announce
                && was_relayed
                && persist_holder_claim(&cached_path, claim).is_ok()
            {
                self.announce.announce_inventory().await;
            }
            return WarmOutcome::AlreadyHeld;
        }

        let Some(_claim) = self.registry.claim(capsule.to_string()) else {
            return WarmOutcome::AlreadyWarming;
        };

        // 1. THE ROOT OF TRUST. Resolve the generation's anchored root from the CHAIN before any peer is
        //    contacted. This ordering is deliberate: the verifier is constructed from the chain's answer,
        //    so there is no point in the flow at which a peer's answer could become the anchor.
        let Some((store, chain_root)) = self.resolve_chain_anchor(store_hex, root_hex).await else {
            tracing::info!(
                store = %super::serve_log::SafeId::new(store_hex),
                root = %super::serve_log::SafeId::new(root_hex),
                outcome = "refused",
                reason = "no chain anchor",
                "capsule warm: refusing to pull a generation the chain cannot confirm"
            );
            return WarmOutcome::Refused(WarmFailure::NoChainAnchor);
        };
        let verifier = ChainAnchoredModuleVerifier::for_generation(store, chain_root);

        // 2. Pull, staging OUTSIDE the cache (see the module docs: a file at the cache path IS an
        //    announcement). dig-download's `FileSink` is used as-is — it implements the fail-closed
        //    `truncate` + `read_at` the engine's promotion probe requires, so there is no bespoke sink
        //    here to accidentally inherit a default from.
        let staged = self.paths.staged_module(&capsule);
        // Bytes + checkpoint as ONE value, so no failure path below can erase half of a partial.
        let pull = StagedPull::new(&staged, self.state_store.as_ref(), store_hex, root_hex);
        let sink = dig_download::FileSink::new(&staged);
        let downloader = dig_download::ModuleDownloader::new(
            Arc::clone(&self.locator),
            Arc::clone(&self.transport),
            Arc::new(verifier.clone()),
            Arc::clone(&self.state_store),
            config,
        );

        // The boundary is scoped to the download and nothing else, so it is reported the moment the
        // pull ends — on success, on failure, and on a PANIC that unwinds through it. A failed pull is
        // exactly the one that spent relay budget on hops that did not deliver, and leaving its ledger
        // entry behind would charge the NEXT pull of this capsule for it (dig-node#333 review).
        let pulled = {
            let _boundary = PullBoundary::new(self.pull_lifecycle.as_ref(), store_hex, root_hex);
            downloader.download(store_hex, root_hex, &sink).await
        };

        // 3. ONLY `Ok` may lead to a holder claim. Not finalize-observed, not partial staging, not an
        //    `Err` that happened to leave bytes behind.
        // `match`, NOT `let…else`: a `let…else` cannot bind the `Err`, so every failed warm in the
        // field reported the one constant string "pull failed" and the download error — the only thing
        // that says WHICH holder refused, timed out, or served an unverifiable chunk — was dropped on
        // the floor. Four live diagnostic rounds produced no error text for exactly that reason
        // (dig_ecosystem#3128). The reason logged here is the pull's own `Display`, which dig-download
        // composes from this node's vocabulary plus SENTINELLED peer ids, so surfacing it cannot let a
        // peer author what this node logs (#1603).
        let bytes = match pulled {
            Ok(bytes) => bytes,
            Err(error) => {
                // NOT an unconditional discard. Erasing the partial here is what made dig-download's
                // resume machinery structurally unreachable for capsule warms (#328): the checkpoint
                // survived while the bytes it described did not, so every retry restarted from offset 0.
                let disposition = StagingDisposition::for_failure(&error);
                disposition.apply(&pull).await;
                tracing::info!(
                    store = %super::serve_log::SafeId::new(store_hex),
                    root = %super::serve_log::SafeId::new(root_hex),
                    outcome = "refused",
                    reason = %error,
                    staging = ?disposition,
                    "capsule warm: pull did not complete; this node is NOT a holder"
                );
                return WarmOutcome::Refused(WarmFailure::PullFailed {
                    reason: error.to_string(),
                });
            }
        };

        // 4. Promote into the cache, re-proving the artifact is the admitted one, THEN announce.
        let cached = self.paths.cached_module(&capsule);
        match promote_into_cache(&staged, &cached, &verifier, claim) {
            Ok(promoted) => {
                pull.erase().await;
                // The ONE step a relayed warm skips. Everything above it — the chain anchor, the
                // merkle verification, the promote-recheck — ran identically, so the bytes are equally
                // trustworthy; what differs is whether this node CLAIMS them (see [`HolderClaim`]).
                if claim == HolderClaim::Announce {
                    self.announce.announce_inventory().await;
                }
                tracing::info!(
                    store = %super::serve_log::SafeId::new(store_hex),
                    root = %super::serve_log::SafeId::new(root_hex),
                    outcome = "held",
                    bytes = promoted,
                    announced = claim == HolderClaim::Announce,
                    "capsule warm: whole capsule verified + cached"
                );
                WarmOutcome::Held { bytes: promoted }
            }
            Err(failure) => {
                pull.erase().await;
                tracing::warn!(
                    store = %super::serve_log::SafeId::new(store_hex),
                    root = %super::serve_log::SafeId::new(root_hex),
                    outcome = "refused",
                    reason = ?failure,
                    verified_bytes = bytes,
                    "capsule warm: refusing to promote/announce a capsule that is not the verified one"
                );
                WarmOutcome::Refused(failure)
            }
        }
    }

    /// The `(store_id, chain_root)` this generation is anchored at, or `None` if the chain cannot
    /// confirm it.
    ///
    /// Uses `verify_pinned_root` — the BOUNDED check — so the requested generation is confirmed against
    /// the chain without the full lineage walk that aborts on one unparseable intermediate spend
    /// (#747). The root returned is the one the CALLER asked for, and it is returned only once the chain
    /// has confirmed it; a generation the chain does not confirm yields `None` and the pull never
    /// starts.
    async fn resolve_chain_anchor(
        &self,
        store_hex: &str,
        root_hex: &str,
    ) -> Option<(Bytes32, Bytes32)> {
        let store = Bytes32(decode_id(store_hex)?);
        let root = Bytes32(decode_id(root_hex)?);
        self.anchor_resolver
            .verify_pinned_root(&store.0, root)
            .await
            .ok()
            .map(|()| (store, root))
    }
}

/// Start a background capsule warm for `(store_hex, root_hex)` and return immediately.
///
/// The read that triggered this MUST NOT wait for it: a whole-capsule pull is orders of magnitude
/// larger than the resource read that revealed the capsule, and the read's latency is user-facing. A
/// failed warm never affects the read.
pub fn spawn_capsule_warm(warmer: Arc<CapsuleWarmer>, store_hex: String, root_hex: String) {
    tokio::spawn(async move {
        warmer.warm(&store_hex, &root_hex).await;
    });
}

/// [`spawn_capsule_warm`]'s relay twin: pull `(store_hex, root_hex)` ON A REQUESTOR'S BEHALF, in the
/// background, claiming nothing.
///
/// The claim is the whole difference — a relayed capsule is cached so the hop can serve its windows
/// and is NOT announced, so relaying never turns this node into an advertised holder of a stranger's
/// choosing ([`HolderClaim::Suppress`]).
///
/// Spawned rather than awaited because the requestor's ask must not be held open for the length of a
/// third-party transfer (dig-node#333). Re-entrant: [`WarmRegistry`] admits one warm per generation,
/// so a second request for the same capsule joins the running pull instead of starting a rival one.
pub fn spawn_relayed_capsule_warm(warmer: Arc<CapsuleWarmer>, store_hex: String, root_hex: String) {
    tokio::spawn(async move {
        warmer.warm_relayed(&store_hex, &root_hex).await;
    });
}

/// Decode a canonical 64-hex id into 32 raw bytes.
fn decode_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use digstore_core::datasection::{
        encode_blob, encode_chunk_pool, encode_key_table, encode_merkle_nodes, SectionId,
    };
    use digstore_core::merkle::{resource_leaf, MerkleTree};
    use digstore_core::serving::concat_output;
    use digstore_core::KeyTableEntry;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const STORE: [u8; 32] = [0xa1; 32];

    fn hex32(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The single fixed resource every reshare fixture serves: one resource with a known `static_key`
    /// and one content chunk. Its merkle root is DERIVED from the content (a preimage of an arbitrary
    /// root cannot be chosen), so [`chain_root`] is whatever this content folds to.
    fn faithful_resource() -> ([u8; 32], Vec<u8>) {
        ([0x01; 32], b"reshare capsule content".to_vec())
    }

    /// The chain-anchored generation root the reshare fixtures commit — the merkle root of
    /// [`faithful_resource`]'s content. Deterministic, so every fixture and every verifier/resolver in
    /// this module agree on the same root.
    fn chain_root() -> [u8; 32] {
        let (_static_key, chunk) = faithful_resource();
        let leaf = resource_leaf(&concat_output(&[chunk.as_slice()]));
        MerkleTree::from_leaves(vec![leaf]).root().0
    }

    /// A FAITHFUL `.dig`-shaped module committing `store` + `root` whose `ChunkPool`/`KeyTable`/
    /// `MerkleNodes` reproduce `root` under the hardened admit gate (rule 5, #2246). Callers pass
    /// [`chain_root`] as `root`; the served content folds to exactly that.
    fn module_committing(store: [u8; 32], root: [u8; 32]) -> Vec<u8> {
        let (static_key, chunk) = faithful_resource();
        let leaf = resource_leaf(&concat_output(&[chunk.as_slice()]));
        let leaves = vec![leaf];
        let entries = vec![KeyTableEntry {
            static_key: Bytes32(static_key),
            generation: Bytes32(root),
            chunk_indices: vec![0],
            total_size: chunk.len() as u64,
        }];
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&entries)),
            (
                SectionId::ChunkPool as u16,
                encode_chunk_pool(&[chunk.as_slice()]),
            ),
            (SectionId::MerkleNodes as u16, encode_merkle_nodes(&leaves)),
        ])
    }

    /// The directory is OWNED by the returned guard: `TempDir`'s `Drop` removes the tree,
    /// including on an unwind, so a failing assertion cannot leak it (dig-node#370).
    fn temp_dir(tag: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("dig-node-warm-{tag}-"))
            .tempdir()
            .expect("a temp dir")
    }

    /// Counts announces, so "no announce happened" is an assertable property.
    #[derive(Default)]
    struct AnnounceSpy {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl AnnounceHolder for AnnounceSpy {
        async fn announce_inventory(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    // -- the pre-announce re-check ------------------------------------------------------------------

    /// An in-memory [`dig_download::ModuleReader`] over staged bytes — dig-download 0.15 hands the
    /// verifier a reader rather than a slice, so the tests supply the same shape the engine does.
    struct SliceReader(Vec<u8>);

    #[async_trait::async_trait]
    impl dig_download::ModuleReader for SliceReader {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        async fn read_at(
            &self,
            offset: u64,
            len: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            let start = (offset as usize).min(self.0.len());
            let end = start.saturating_add(len as usize).min(self.0.len());
            Ok(self.0[start..end].to_vec())
        }
    }

    /// **Proves:** a staged artifact that IS the admitted one is promoted into the cache.
    #[test]
    fn promotes_the_artifact_the_gate_admitted() {
        let dir = temp_dir("promote-ok");
        let module = module_committing(STORE, chain_root());
        let staged = dir.join("staged.dig");
        std::fs::write(&staged, &module).unwrap();

        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(chain_root()));
        assert_eq!(
            futures::executor::block_on(dig_download::ModuleAnchorVerifier::verify_module_anchor(
                &verifier,
                &SliceReader(module.clone()),
                &hex32(STORE),
                &hex32(chain_root())
            )),
            dig_download::ModuleAnchor::Anchored
        );

        let cached = dir.join("cached.module");
        assert_eq!(
            promote_into_cache(&staged, &cached, &verifier, HolderClaim::Announce),
            Ok(module.len() as u64)
        );
        assert_eq!(std::fs::read(&cached).unwrap(), module);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a successful promotion bumps the #1991 `CACHE_REFETCH_COUNT` telemetry counter —
    /// the reshare-warm land counts toward `refetch_count` exactly like `sync_module_from`'s land does,
    /// since this is the SEPARATE write-then-rename path that never routes through it.
    #[test]
    fn promoting_an_admitted_artifact_bumps_the_refetch_counter() {
        let dir = temp_dir("promote-refetch-counter");
        let module = module_committing(STORE, chain_root());
        let staged = dir.join("staged.dig");
        std::fs::write(&staged, &module).unwrap();
        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(chain_root()));
        futures::executor::block_on(dig_download::ModuleAnchorVerifier::verify_module_anchor(
            &verifier,
            &SliceReader(module.clone()),
            &hex32(STORE),
            &hex32(chain_root()),
        ));

        // `>=` rather than exact `==`: `CACHE_REFETCH_COUNT` is a PROCESS-GLOBAL atomic shared with
        // every other test in the crate's `cargo test`/`cargo llvm-cov` process, including several
        // that land real capsules concurrently — a concurrent land can only make the delta BIGGER,
        // never smaller, so `>= before + 1` is the strongest claim that stays deterministic under
        // full-suite parallelism while still proving THIS promotion contributed at least one bump.
        let before = crate::CACHE_REFETCH_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        let cached = dir.join("cached.module");
        assert!(promote_into_cache(&staged, &cached, &verifier, HolderClaim::Announce).is_ok());
        let after = crate::CACHE_REFETCH_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "a successful promotion counts as at least one refetch (before={before}, after={after})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** an artifact TAMPERED AFTER the gate admitted it is refused, so the node never caches
    /// (and therefore never announces) a capsule that is not the verified one.
    /// **Catches:** trusting `download() == Ok` alone — the "verified artifact != promoted artifact"
    /// poisoning, which is invisible from inside the engine because the engine verified a blob it no
    /// longer holds.
    #[test]
    fn refuses_an_artifact_tampered_after_the_gate_admitted_it() {
        let dir = temp_dir("promote-tampered");
        let module = module_committing(STORE, chain_root());
        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(chain_root()));
        assert_eq!(
            futures::executor::block_on(dig_download::ModuleAnchorVerifier::verify_module_anchor(
                &verifier,
                &SliceReader(module.clone()),
                &hex32(STORE),
                &hex32(chain_root())
            )),
            dig_download::ModuleAnchor::Anchored
        );

        // The gate admitted `module`; what is on disk is something else (one flipped byte, and a
        // trailing tail — both invisible to a caller that only checks the Ok).
        let staged = dir.join("staged.dig");
        let mut tampered = module.clone();
        tampered.extend_from_slice(b"trailing garbage");
        std::fs::write(&staged, &tampered).unwrap();

        let cached = dir.join("cached.module");
        assert_eq!(
            promote_into_cache(&staged, &cached, &verifier, HolderClaim::Announce),
            Err(WarmFailure::PromotedArtifactMismatch)
        );
        assert!(
            !cached.exists(),
            "a mismatched artifact must never reach the cache path — its existence IS the holder claim"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a staged artifact with NO admitted digest behind it is refused — an artifact no gate
    /// ever saw cannot be promoted just because it exists.
    #[test]
    fn refuses_to_promote_an_artifact_no_gate_admitted() {
        let dir = temp_dir("promote-ungated");
        let staged = dir.join("staged.dig");
        std::fs::write(&staged, module_committing(STORE, chain_root())).unwrap();
        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(chain_root()));

        let cached = dir.join("cached.module");
        assert_eq!(
            promote_into_cache(&staged, &cached, &verifier, HolderClaim::Announce),
            Err(WarmFailure::PromotedArtifactMismatch)
        );
        assert!(!cached.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- announce only on Ok -----------------------------------------------------------------------

    /// A locator that finds nobody, so `download()` fails at its first step.
    struct NoHolders;

    #[async_trait::async_trait]
    impl dig_download::ProviderLocator for NoHolders {
        async fn find_providers(
            &self,
            _content: &dig_download::ContentId,
        ) -> Result<Vec<dig_download::ProviderRecord>, dig_download::DownloadError> {
            Ok(vec![])
        }
    }

    /// A transport that is never reached (the locate above fails first).
    struct UnusedTransport;

    #[async_trait::async_trait]
    impl dig_download::ModuleTransport for UnusedTransport {
        async fn get_module_info(
            &self,
            peer: &str,
            _store_id: &str,
            _root: &str,
        ) -> Result<dig_download::ModuleInfo, dig_download::DownloadError> {
            Err(dig_download::DownloadError::transport(peer, "unused"))
        }
        async fn fetch_module_range(
            &self,
            peer: &str,
            _store_id: &str,
            _root: &str,
            _offset: u64,
            _length: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            Err(dig_download::DownloadError::transport(peer, "unused"))
        }
    }

    /// A resolver that confirms `root` as the anchored generation.
    struct ConfirmingResolver;

    #[async_trait::async_trait]
    impl crate::shared::AnchoredRootResolver for ConfirmingResolver {
        async fn anchored_root(&self, _store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
            Ok(Some(Bytes32(chain_root())))
        }
    }

    /// A resolver that cannot confirm anything (the chain is unreachable).
    struct UnreachableChain;

    #[async_trait::async_trait]
    impl crate::shared::AnchoredRootResolver for UnreachableChain {
        async fn anchored_root(&self, _store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
            Err("chain unreachable".into())
        }
    }

    fn warmer_with(
        resolver: Arc<dyn crate::shared::AnchoredRootResolver>,
        announce: Arc<AnnounceSpy>,
        dir: &Path,
    ) -> Arc<CapsuleWarmer> {
        CapsuleWarmer::new(
            Arc::new(NoHolders),
            Arc::new(UnusedTransport),
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::FileStateStore::new(dir.join("state"))),
            resolver,
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            announce,
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        )
    }

    /// **Proves (#1614):** a warmer stores the EXACT `Arc<WarmRegistry>` it was built with — the property
    /// [`crate::download::NodeContent::wire_capsule_reshare`] relies on to make the reshare leg claim the
    /// node's SHARED gate rather than a fresh one. If `CapsuleWarmer::new` ever cloned into a new registry
    /// instead of keeping the passed `Arc`, the two legs would silently double-pull again.
    /// **Catches:** the reshare warmer being wired with `Arc::new(WarmRegistry::new())` (the pre-#1614
    /// shape) instead of the node's `capsule_acquisition` gate.
    #[test]
    fn a_warmer_shares_the_exact_registry_arc_it_was_built_with() {
        let dir = temp_dir("shared-registry");
        let shared = Arc::new(WarmRegistry::new());
        let warmer = CapsuleWarmer::new(
            Arc::new(NoHolders),
            Arc::new(UnusedTransport),
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::FileStateStore::new(dir.join("state"))),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::clone(&shared),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );
        assert!(
            Arc::ptr_eq(warmer.registry(), &shared),
            "the warmer must claim against the SAME registry instance it was wired with, not a fresh one"
        );
    }

    // -- the failure reason an operator actually reads ---------------------------------------------

    /// A locator that offers exactly ONE holder, so the pull reaches the transport and fails THERE —
    /// the shape a real capsule warm takes. `NoHolders` above cannot exercise this: it fails at the
    /// locate step, before any holder-attributed reason exists to surface.
    struct OneHolder;

    #[async_trait::async_trait]
    impl dig_download::ProviderLocator for OneHolder {
        async fn find_providers(
            &self,
            _content: &dig_download::ContentId,
        ) -> Result<Vec<dig_download::ProviderRecord>, dig_download::DownloadError> {
            Ok(vec![dig_download::ProviderRecord {
                content_key: "cc".repeat(32),
                provider_peer_id: "dd".repeat(32),
                addresses: vec![],
                expires_at: u64::MAX,
                // No mirror-coin pointer: absence is the normal state for a provider (#422).
                unverified_mirror_coin_id: None,
            }])
        }
    }

    /// A holder that refuses the descriptor with a reason only THIS test can produce, so the assertion
    /// below cannot be satisfied by any other string the warm path might log.
    struct RefusingHolder;

    /// The refusal text. Distinctive on purpose: an assertion on a generic word like "failed" would
    /// also match the constant the fix removes.
    const REFUSAL: &str = "holder-refused-the-descriptor-sentinel";

    #[async_trait::async_trait]
    impl dig_download::ModuleTransport for RefusingHolder {
        async fn get_module_info(
            &self,
            peer: &str,
            _store_id: &str,
            _root: &str,
        ) -> Result<dig_download::ModuleInfo, dig_download::DownloadError> {
            Err(dig_download::DownloadError::transport(peer, REFUSAL))
        }
        async fn fetch_module_range(
            &self,
            peer: &str,
            _store_id: &str,
            _root: &str,
            _offset: u64,
            _length: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            Err(dig_download::DownloadError::transport(peer, REFUSAL))
        }
    }

    /// **Proves:** a failed warm carries the pull's OWN holder-attributed error into its outcome,
    /// rather than a constant.
    ///
    /// **Catches:** the shipped `let Ok(bytes) = pulled else { ... reason = "pull failed" }`. A
    /// `let...else` cannot bind the `Err`, so every failed warm in the field reported one fixed
    /// string and four live diagnostic rounds produced no error text at all (dig_ecosystem#3128).
    ///
    /// **Why the VALUE and not the log:** an earlier version of this test read a captured log, and it
    /// passed in isolation while failing in the full suite — `tracing` caches per-callsite interest,
    /// so a scoped subscriber never sees a callsite an earlier global subscriber already registered
    /// as disabled. A cause that lives only in a log is also the shape of the original defect. It now
    /// lives in the return value, where nothing can filter it away.
    ///
    /// **Non-vacuous:** the needle is a sentinel this test's own transport authors and nothing else
    /// in the crate emits, and `NoHolders` above cannot exercise this at all — it fails at the locate
    /// step, before any holder-attributed reason exists.
    #[tokio::test]
    async fn a_failed_warm_carries_the_underlying_cause_not_a_constant() {
        let dir = temp_dir("failure-reason");
        let warmer = CapsuleWarmer::new(
            Arc::new(OneHolder),
            Arc::new(RefusingHolder),
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::FileStateStore::new(dir.join("state"))),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );

        let outcome = warmer.warm(&hex32(STORE), &hex32(chain_root())).await;

        let WarmOutcome::Refused(WarmFailure::PullFailed { reason }) = outcome else {
            panic!("the fixture must drive a failed pull, or this proves nothing; got {outcome:?}");
        };
        assert!(
            reason.contains(REFUSAL),
            "the refusal the holder produced must survive into the warm's own outcome, not be              discarded by a `let...else`; got: {reason}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a pull that ends in `Err` announces NOTHING and leaves no module at the cache path.
    /// **Catches:** announcing on finalize-observed / partial staging / a failed pull — which, because
    /// the announce is driven off cache inventory (#1586), would advertise this node network-wide as an
    /// authoritative holder of garbage.
    #[tokio::test]
    async fn a_failed_pull_announces_nothing() {
        let dir = temp_dir("failed-pull");
        let spy = Arc::new(AnnounceSpy::default());
        let warmer = warmer_with(Arc::new(ConfirmingResolver), Arc::clone(&spy), &dir);

        let outcome = warmer.warm(&hex32(STORE), &hex32(chain_root())).await;

        assert!(matches!(
            outcome,
            WarmOutcome::Refused(WarmFailure::PullFailed { .. })
        ));
        assert_eq!(
            spy.calls.load(Ordering::SeqCst),
            0,
            "a failed pull must never announce this node as a holder"
        );
        assert!(
            !dir.join("cache").join("modules").exists(),
            "no module may appear at the cache path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a warm that actually SUCCEEDS returns `Held`, announces exactly once, leaves the
    /// verified bytes at the CACHE path (byte-identical), and discards the staging artifact.
    ///
    /// **Catches:** every other test in this module exercises a REFUSAL — `PullFailed`,
    /// `NoChainAnchor` (twice), a bad id. None of them can tell the difference between "the wiring
    /// correctly refused" and "the wiring is broken and can only ever refuse" — a `warm()` that always
    /// returned `Refused` would pass all four and ship green. This is the one test that proves the
    /// success path exists at all: `WarmOutcome::Held` is asserted here for the first and only time.
    #[tokio::test]
    async fn a_successful_pull_is_held_cached_and_announced_once() {
        let dir = temp_dir("happy-path");
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let module = module_committing(STORE, chain_root());

        // One real holder, served through dig-download's own mock transport — the SAME production
        // `ModuleDownloader`/`FileSink` path the refusal tests exercise, just with a source that
        // actually answers.
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        let locator = Arc::new(dig_download::testkit::MockProviderLocator::fixed(
            dig_download::testkit::mock_providers(1, &content),
        ));
        let transport = Arc::new(dig_download::testkit::MockModuleTransport::serving(
            &store_hex,
            &root_hex,
            module.clone(),
            8,
        ));

        let spy = Arc::new(AnnounceSpy::default());
        let warmer = CapsuleWarmer::new(
            locator,
            transport,
            Arc::new(crate::seams::dig_peer::NoPullState),
            // In-memory, not `FileStateStore`: the resume-checkpoint backing store is orthogonal to
            // what this test proves (staged->cache promotion + announce-once), and `FileStateStore`'s
            // hex-doubled `module:<64hex>:<64hex>` key exceeds Windows' ~255-char filename limit
            // (verified via a scratch reproduction: `ERROR_INVALID_NAME`, os error 123) — a real sharp
            // edge in the upstream crate worth its own ticket, not something this test should trip over.
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::clone(&spy) as Arc<dyn AnnounceHolder>,
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );

        let outcome = warmer.warm(&store_hex, &root_hex).await;

        assert_eq!(
            outcome,
            WarmOutcome::Held {
                bytes: module.len() as u64
            },
            "a genuinely successful pull must report Held with the verified length"
        );
        assert_eq!(
            spy.calls.load(Ordering::SeqCst),
            1,
            "exactly one announce fires for a successful warm"
        );

        let cached_path = dir
            .join("cache")
            .join("modules")
            .join(&store_hex)
            .join(format!("{root_hex}.dig"));
        assert_eq!(
            std::fs::read(&cached_path).expect("module is at the cache path"),
            module,
            "the cached artifact is byte-identical to the verified module"
        );

        let staged_path = dir
            .join("staging")
            .join("modules")
            .join(format!("{store_hex}-{root_hex}.dig"));
        assert!(
            !staged_path.exists(),
            "staging is discarded once the module has been promoted into the cache"
        );
        assert!(
            !dig_download::staging_path_for(&staged_path).exists(),
            "the download's own .tmp staging file is discarded too"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- resume across a severed transfer (dig-node#328) --------------------------------------------

    /// A holder that serves a bounded number of range fetches and then goes silent, counting the bytes
    /// it actually put on the wire — and that can be REOPENED so a second warm sees the same holder
    /// answering again, exactly as a peer does once a network partition heals.
    ///
    /// It delegates every honest answer to dig-download's own mock, so the descriptor, the chunk hashes
    /// and the served windows are the production shapes; the ONLY thing varied is when the link dies.
    /// That is deliberate: a fixture in which the holder also lied could not tell a resume apart from a
    /// re-fetch forced by a failed re-attribution.
    struct SeveringHolder {
        inner: dig_download::testkit::MockModuleTransport,
        /// How many more `fetchModuleRange` calls this holder will answer before the link is severed.
        budget: AtomicUsize,
        /// Total bytes this holder has put on the wire across every attempt.
        served: std::sync::atomic::AtomicU64,
    }

    impl SeveringHolder {
        fn severing_after(
            inner: dig_download::testkit::MockModuleTransport,
            fetches: usize,
        ) -> Self {
            SeveringHolder {
                inner,
                budget: AtomicUsize::new(fetches),
                served: std::sync::atomic::AtomicU64::new(0),
            }
        }

        /// The partition heals: the holder answers freely again.
        fn reopen(&self) {
            self.budget.store(usize::MAX, Ordering::SeqCst);
        }

        fn served_bytes(&self) -> u64 {
            self.served.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl dig_download::ModuleTransport for SeveringHolder {
        async fn get_module_info(
            &self,
            provider_peer_id: &str,
            store_id: &str,
            root: &str,
        ) -> Result<dig_download::ModuleInfo, dig_download::DownloadError> {
            self.inner
                .get_module_info(provider_peer_id, store_id, root)
                .await
        }

        async fn fetch_module_range(
            &self,
            provider_peer_id: &str,
            store_id: &str,
            root: &str,
            offset: u64,
            length: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            let spend = self
                .budget
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    (left > 0).then(|| left.saturating_sub(1))
                });
            if spend.is_err() {
                return Err(dig_download::DownloadError::transport(
                    provider_peer_id,
                    "link severed mid-transfer",
                ));
            }
            let bytes = self
                .inner
                .fetch_module_range(provider_peer_id, store_id, root, offset, length)
                .await?;
            self.served.fetch_add(bytes.len() as u64, Ordering::SeqCst);
            Ok(bytes)
        }
    }

    /// The chunk size every #328 fixture serves at. The resume unit is a CHUNK, not a byte, so the
    /// fixture is sized in chunks: this splits the capsule into ~25 of them, which leaves room to sever
    /// the link strictly INSIDE the capsule (neither at offset 0, where a resume is indistinguishable
    /// from a restart, nor after the last chunk, where there is nothing left to resume).
    const RESUME_CHUNK_BYTES: usize = 8;

    /// Build a warmer over ONE [`SeveringHolder`], sharing `state` so two successive warms see the same
    /// resume checkpoints — the cross-attempt persistence the real node has via `FileStateStore`.
    fn severing_warmer(
        dir: &Path,
        transport: &Arc<SeveringHolder>,
        state: &Arc<dyn dig_download::StateStore>,
    ) -> Arc<CapsuleWarmer> {
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(
                dig_download::testkit::mock_providers(1, &content),
            )),
            Arc::clone(transport) as Arc<dyn dig_download::ModuleTransport>,
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::clone(state),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        )
    }

    /// The staging path a warm of `(STORE, chain_root())` under `dir` writes through.
    fn staged_module_path(dir: &Path) -> PathBuf {
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        dir.join("staging")
            .join("modules")
            .join(format!("{store_hex}-{root_hex}.dig"))
    }

    /// **Proves (dig-node#328):** a warm whose transfer is severed mid-capsule keeps what it staged, so
    /// the NEXT warm fetches only the missing bytes.
    ///
    /// **The assertion is a BYTE COUNT, not completion.** That distinction is the whole ticket: the
    /// broken code completed the second attempt too — it just paid for the entire capsule again. Field
    /// measurement on v0.143.1 (a 134,968,945-byte capsule cut at 34,603,008 staged bytes) had attempt 2
    /// transfer 182,219,987 bytes against an uninterrupted control of 182,184,850 — 0.02% MORE than
    /// starting from scratch. A test asserting `Held` passes against exactly that.
    ///
    /// **Why the fixture is shaped this way:**
    /// - the second attempt uses the SAME holder, healed, rather than a second honest peer: a fresh
    ///   holder would make "attempt 2 was cheap" explainable by source selection instead of by resume;
    /// - the state store is shared across both warms, because a checkpoint that did not survive would
    ///   make the resume impossible for a reason that has nothing to do with the staged bytes;
    /// - the control assertions require attempt 1 to have staged SOMETHING and attempt 2 to have fetched
    ///   SOMETHING. Without them a fixture that served nothing at all, or one that had already completed
    ///   in attempt 1, would satisfy "attempt 2 < whole capsule" vacuously.
    #[tokio::test]
    async fn a_severed_warm_resumes_from_its_partial_instead_of_refetching_the_capsule() {
        let dir = temp_dir("resume-after-sever");
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let module = module_committing(STORE, chain_root());
        let capsule_bytes = module.len() as u64;
        let chunks = module.len().div_ceil(RESUME_CHUNK_BYTES);
        assert!(
            chunks >= 4,
            "the fixture must have several chunks or a partial cannot exist ({chunks} chunk(s))"
        );

        let transport = Arc::new(SeveringHolder::severing_after(
            dig_download::testkit::MockModuleTransport::serving(
                &store_hex,
                &root_hex,
                module.clone(),
                RESUME_CHUNK_BYTES,
            ),
            chunks / 2,
        ));
        let state: Arc<dyn dig_download::StateStore> =
            Arc::new(dig_download::InMemoryStateStore::new());
        let warmer = severing_warmer(&dir, &transport, &state);

        // ATTEMPT 1 — the link dies half way through the capsule.
        let severed = warmer.warm(&store_hex, &root_hex).await;
        let staged_in_attempt_1 = transport.served_bytes();

        assert!(
            matches!(
                severed,
                WarmOutcome::Refused(WarmFailure::PullFailed { .. })
            ),
            "a severed transfer must refuse the warm, not land a partial capsule: {severed:?}"
        );
        assert!(
            staged_in_attempt_1 > 0 && staged_in_attempt_1 < capsule_bytes,
            "the control: attempt 1 must stage a genuine PARTIAL ({staged_in_attempt_1} of \
             {capsule_bytes} bytes)"
        );
        let partial = dig_download::staging_path_for(&staged_module_path(&dir));
        assert_eq!(
            std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0),
            staged_in_attempt_1,
            "the partial must SURVIVE the failed warm — this is the byte-for-byte fact #328 measured \
             absent in the field"
        );

        // ATTEMPT 2 — the partition heals and the same holder answers again.
        transport.reopen();
        let outcome = warmer.warm(&store_hex, &root_hex).await;
        let served_in_attempt_2 = transport.served_bytes() - staged_in_attempt_1;

        assert_eq!(
            outcome,
            WarmOutcome::Held {
                bytes: capsule_bytes
            },
            "the resumed warm must land the whole capsule"
        );
        assert!(
            served_in_attempt_2 > 0,
            "the control: attempt 2 must actually fetch the missing bytes, or this proves nothing"
        );
        assert!(
            served_in_attempt_2 < capsule_bytes,
            "attempt 2 transferred {served_in_attempt_2} of {capsule_bytes} bytes — a whole-capsule \
             re-download, which is the #328 defect exactly"
        );
        assert_eq!(
            served_in_attempt_2,
            capsule_bytes - staged_in_attempt_1,
            "attempt 2 must fetch the missing bytes and ONLY the missing bytes"
        );
        assert_eq!(
            std::fs::read(cached_module_path(&dir)).expect("the capsule is cached"),
            module,
            "the capsule assembled from a partial plus a resume is byte-identical to the real one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves (dig-node#328, the security half):** a pull that fails VERIFICATION still erases what it
    /// staged. Those bytes verified only against a descriptor the final gates proved false, so leaving
    /// them would let a hostile hop plant bytes a later honest range completes around (NC-12).
    ///
    /// **Why this is a separate test on a DIFFERENT holder behaviour:** the fix is a two-branch
    /// decision, and a suite proving only the keep branch is satisfied by deleting `discard_staging`
    /// outright. The holder here serves honest chunk bytes and honest per-chunk hashes — so every chunk
    /// is genuinely STAGED and there is something on disk to erase — and lies only in the whole-blob
    /// `module_hash`. A holder that served nothing could not exhibit the property at all.
    #[tokio::test]
    async fn a_verification_failure_still_discards_what_it_staged() {
        let dir = temp_dir("verify-fail-discards");
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let module = module_committing(STORE, chain_root());
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");

        let transport = Arc::new(
            dig_download::testkit::MockModuleTransport::serving(
                &store_hex,
                &root_hex,
                module.clone(),
                RESUME_CHUNK_BYTES,
            )
            .with_corrupt_module_hash(),
        );
        // Held, not inlined: dig-node#332 is about what SURVIVES in this store after the failure, and
        // an inlined store cannot be read back.
        let state: Arc<dyn dig_download::StateStore> =
            Arc::new(dig_download::InMemoryStateStore::new());
        let warmer = CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(
                dig_download::testkit::mock_providers(1, &content),
            )),
            transport,
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::clone(&state),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );

        let outcome = warmer.warm(&store_hex, &root_hex).await;

        assert!(
            matches!(
                outcome,
                WarmOutcome::Refused(WarmFailure::PullFailed { .. })
            ),
            "a blob that fails the whole-module hash gate must be refused: {outcome:?}"
        );
        let staged = staged_module_path(&dir);
        assert!(
            !staged.exists() && !dig_download::staging_path_for(&staged).exists(),
            "bytes attributable only to a proven-false descriptor must not survive the failure"
        );
        assert!(
            !cached_module_path(&dir).exists(),
            "nothing may reach the cache path"
        );
        // dig-node#332: the checkpoint is the OTHER half of the same partial. Left behind, it claims
        // chunks that are no longer on disk, so the next warm re-attributes each one and logs the
        // per-chunk warning an operator reads as hostile content — on a routine discard.
        assert!(
            state
                .load(&dig_download::module_download_key(&store_hex, &root_hex))
                .await
                .expect("the state store is readable")
                .is_none(),
            "a discarded partial must leave no resume checkpoint behind"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** the keep-or-erase decision is made per FAILURE KIND — the unit-level companion to the
    /// two behavioural tests above, so a future error variant's disposition is readable without
    /// reconstructing a whole pull.
    #[test]
    fn only_a_verification_failure_erases_the_partial() {
        use dig_download::DownloadError as E;
        assert_eq!(
            StagingDisposition::for_failure(&E::Verify(dig_download::VerifyError::Metadata(
                "assembled module_hash mismatch".into()
            ))),
            StagingDisposition::Discard,
            "a proven-false descriptor's bytes are erased"
        );
        for transport_failure in [
            E::transport(hex32(STORE), "connection reset"),
            E::Timeout {
                provider: hex32(STORE),
            },
            E::NoProviders { needed: 3 },
            E::Cancelled,
        ] {
            assert_eq!(
                StagingDisposition::for_failure(&transport_failure),
                StagingDisposition::Preserve,
                "a transport failure leaves verified partial bytes to resume from: \
                 {transport_failure}"
            );
        }
    }

    /// Build a warmer over a REAL, answering holder for `(STORE, chain_root())`, staging + caching
    /// under `dir`, announcing through `spy`.
    ///
    /// Extracted so the relay pair below can hold every input constant and vary exactly ONE thing —
    /// which entry point is called. Two independently-constructed warmers would leave "the relayed one
    /// simply had no working holder" as an untested explanation for its silence.
    fn serving_warmer(dir: &Path, spy: &Arc<AnnounceSpy>, module: Vec<u8>) -> Arc<CapsuleWarmer> {
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(
                dig_download::testkit::mock_providers(1, &content),
            )),
            Arc::new(dig_download::testkit::MockModuleTransport::serving(
                &store_hex, &root_hex, module, 8,
            )),
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::clone(spy) as Arc<dyn AnnounceHolder>,
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        )
    }

    /// The cache path whose EXISTENCE is this node's holder claim, under `dir`.
    fn cached_module_path(dir: &Path) -> std::path::PathBuf {
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        dir.join("cache")
            .join("modules")
            .join(&store_hex)
            .join(format!("{root_hex}.dig"))
    }

    /// Records every pull boundary the warmer reports, so a test can assert the CALL rather than the
    /// ledger it happens to drive.
    #[derive(Default)]
    struct RecordingLifecycle {
        finished: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl crate::seams::dig_peer::PullLifecycle for RecordingLifecycle {
        fn pull_finished(&self, store_id: &str, root: &str) {
            self.finished
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((store_id.to_string(), root.to_string()));
        }
    }

    /// **Proves (dig-node#333 re-gate):** the WARMER reports the end of every pull — the succeeding
    /// one and, more importantly, the failing one.
    ///
    /// **Why this test and not only the ledger's own:** `RelayWaitBudget::release` being correct says
    /// nothing about whether anything calls it, and a per-pull ledger nobody ends is exactly the
    /// daemon-lifetime bug this fixes. This drives the real `warm` entry point and asserts the seam is
    /// invoked, with the capsule's own ids.
    ///
    /// **Why the FAILING pull is the load-bearing half:** a failed pull is precisely the one that
    /// spent relay budget on hops that did not deliver, so an implementation that reports only on
    /// success leaves the worst case unreleased. It is also the easy mistake — a `?` or an early
    /// return placed above the report.
    #[tokio::test]
    async fn a_warmer_reports_the_end_of_every_pull_including_a_failed_one() {
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));

        // FAILING pull: no holder can be located at all.
        let failed_dir = temp_dir("lifecycle-failed");
        let failed_spy = Arc::new(RecordingLifecycle::default());
        let failed = CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(Vec::new())),
            Arc::new(dig_download::testkit::MockModuleTransport::serving(
                &store_hex,
                &root_hex,
                Vec::new(),
                8,
            )),
            Arc::clone(&failed_spy) as Arc<dyn crate::seams::dig_peer::PullLifecycle>,
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: failed_dir.join("staging"),
                cache_dir: failed_dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );

        let outcome = failed.warm(&store_hex, &root_hex).await;
        assert!(
            matches!(outcome, WarmOutcome::Refused(_)),
            "the control: this pull must genuinely FAIL, or the report below is the success path in              disguise: {outcome:?}"
        );
        assert_eq!(
            failed_spy
                .finished
                .lock()
                .expect("lifecycle lock")
                .as_slice(),
            &[(store_hex.clone(), root_hex.clone())],
            "a FAILED pull must still report its end, naming the capsule — it is the pull most              likely to have spent relay budget on hops that delivered nothing"
        );

        // SUCCEEDING pull: the same report, so the seam is not failure-only either.
        let ok_dir = temp_dir("lifecycle-ok");
        let ok_spy = Arc::new(RecordingLifecycle::default());
        let module = module_committing(STORE, chain_root());
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        let succeeded = CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(
                dig_download::testkit::mock_providers(1, &content),
            )),
            Arc::new(dig_download::testkit::MockModuleTransport::serving(
                &store_hex, &root_hex, module, 8,
            )),
            Arc::clone(&ok_spy) as Arc<dyn crate::seams::dig_peer::PullLifecycle>,
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: ok_dir.join("staging"),
                cache_dir: ok_dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );

        let outcome = succeeded.warm(&store_hex, &root_hex).await;
        assert!(
            matches!(outcome, WarmOutcome::Held { .. }),
            "the control: this pull must genuinely SUCCEED: {outcome:?}"
        );
        assert_eq!(
            ok_spy.finished.lock().expect("lifecycle lock").len(),
            1,
            "a successful pull reports its end exactly once"
        );

        let _ = std::fs::remove_dir_all(&failed_dir);
        let _ = std::fs::remove_dir_all(&ok_dir);
    }

    /// A holder whose descriptor ask PANICS — the shape a real bug in the pull takes.
    struct PanickingHolder;

    #[async_trait::async_trait]
    impl dig_download::ModuleTransport for PanickingHolder {
        async fn get_module_info(
            &self,
            _provider_peer_id: &str,
            _store_id: &str,
            _root: &str,
        ) -> Result<dig_download::ModuleInfo, dig_download::DownloadError> {
            panic!("a bug inside the pull");
        }

        async fn fetch_module_range(
            &self,
            _provider_peer_id: &str,
            _store_id: &str,
            _root: &str,
            _offset: u64,
            _length: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            unreachable!("the descriptor panics first");
        }
    }

    /// **Proves (dig-node#333 re-gate 3):** a pull that PANICS still reports its end, so the relay-wait
    /// ledger cannot leak an entry.
    ///
    /// **Why this is reachable rather than theoretical:** the tier-0 precache path runs
    /// `run_round -> fetch_and_cache -> warm_capped -> download` inside
    /// [`crate::shared::panic_guard::catch_iteration`], added so a panic there is SURVIVED, and this
    /// crate does not build with `panic = "abort"`. A plain statement after the `.await` is skipped by
    /// the unwind, the task then continues, and the entry is never released.
    ///
    /// **What the leak costs, which is why this is not tidiness:** the capsule becomes permanently
    /// ineligible for the relay path, and the resulting exhaustion is composed into a transport error
    /// NAMING A PEER — which `SPEC.md` §21.1, as amended by this same change, says MUST NOT happen.
    ///
    /// **The fixture is the production guard, driven by a production panic**, through the same
    /// `AssertUnwindSafe(...).catch_unwind()` the tier-0 loop uses, so it exercises the unwind rather
    /// than simulating it.
    #[tokio::test]
    async fn a_pull_that_panics_still_reports_its_end() {
        use futures::FutureExt;

        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let dir = temp_dir("lifecycle-panic");
        let spy = Arc::new(RecordingLifecycle::default());
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        let warmer = CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(
                dig_download::testkit::mock_providers(1, &content),
            )),
            Arc::new(PanickingHolder),
            Arc::clone(&spy) as Arc<dyn crate::seams::dig_peer::PullLifecycle>,
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        );

        // The panic message is expected; keep it out of the test log so a real panic stays visible.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::AssertUnwindSafe(warmer.warm(&store_hex, &root_hex))
            .catch_unwind()
            .await;
        std::panic::set_hook(previous);

        assert!(
            outcome.is_err(),
            "the control: the pull must genuinely PANIC and be caught, or the report below is just              the ordinary return path"
        );
        assert_eq!(
            spy.finished.lock().expect("lifecycle lock").as_slice(),
            &[(store_hex.clone(), root_hex.clone())],
            "an unwinding pull must still report its end — a statement after the await is skipped by              the unwind, and the tier-0 catch_unwind then continues with the entry leaked"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves (dig-node#276, unit 4):** a capsule pulled ON A STRANGER'S BEHALF lands in the cache —
    /// so the relayed windows can be served from it — and announces NOTHING, while the *same pull,
    /// through the same holder, of the same bytes*, driven for this node's OWN sake announces exactly
    /// once.
    ///
    /// **Catches:** the amplification hole the relay leg would otherwise reopen one level up. The
    /// `origin != Local` reshare refusal exists so a stranger cannot drive this node into caching AND
    /// DHT-announcing capsules of the attacker's choosing; a relay that pulls a whole capsule for a
    /// stranger and then announces it hands that exact primitive back, with no forged message and no
    /// privileged access required.
    ///
    /// **Why BOTH halves, and why they share `serving_warmer`:** an assertion that the relayed pull
    /// announces zero times is satisfied identically by a suppression that works and by a warmer whose
    /// announce is broken, whose holder never answers, or whose chain never confirms — every one of
    /// which would also make a legitimate reshare silent. The `Announce` half is the truthful control
    /// that distinguishes them: it is the same code, the same fixture and the same holder, differing
    /// only in the [`HolderClaim`] the entry point names.
    #[tokio::test]
    async fn a_relayed_capsule_is_cached_without_announcing_while_a_local_one_announces() {
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let module = module_committing(STORE, chain_root());

        // RELAYED — pulled for a stranger.
        let relay_dir = temp_dir("relayed-warm");
        let relay_spy = Arc::new(AnnounceSpy::default());
        let relayed = serving_warmer(&relay_dir, &relay_spy, module.clone())
            .warm_relayed(&store_hex, &root_hex)
            .await;

        // LOCAL — the identical pull, for this node's own sake. The control.
        let local_dir = temp_dir("local-warm");
        let local_spy = Arc::new(AnnounceSpy::default());
        let local = serving_warmer(&local_dir, &local_spy, module.clone())
            .warm(&store_hex, &root_hex)
            .await;

        let held = WarmOutcome::Held {
            bytes: module.len() as u64,
        };
        assert_eq!(
            local, held,
            "the control must genuinely succeed, or its announce count proves nothing"
        );
        assert_eq!(
            relayed, held,
            "a relayed pull still verifies and caches — it is the holder CLAIM that is withheld"
        );

        assert_eq!(
            local_spy.calls.load(Ordering::SeqCst),
            1,
            "a warm this node drove for itself announces exactly once"
        );
        assert_eq!(
            relay_spy.calls.load(Ordering::SeqCst),
            0,
            "a warm driven by a stranger must never advertise this node as a holder of it"
        );

        // The bytes ARE cached in both cases: the relay serves its requestor's windows from the same
        // artifact a holder serves from, byte-identically, so the requestor needs no second code path.
        for dir in [&relay_dir, &local_dir] {
            assert_eq!(
                std::fs::read(cached_module_path(dir)).expect("module is at the cache path"),
                module,
                "the verified capsule is cached whether or not it was announced"
            );
        }

        let _ = std::fs::remove_dir_all(&relay_dir);
        let _ = std::fs::remove_dir_all(&local_dir);
    }

    /// A second store id, so one cache directory can hold a RELAYED capsule and a genuinely-HELD one
    /// side by side. Both commit the same content-derived [`chain_root`]; only the store differs, which
    /// is enough to give them distinct DHT content ids.
    const LOCAL_STORE: [u8; 32] = [0xb2; 32];

    /// A warmer serving `module` for `store` into the SHARED cache under `dir` — the multi-store variant
    /// of [`serving_warmer`], so one cache can be populated by two different pulls.
    fn serving_warmer_for(
        dir: &Path,
        spy: &Arc<AnnounceSpy>,
        store: [u8; 32],
        module: Vec<u8>,
    ) -> Arc<CapsuleWarmer> {
        let (store_hex, root_hex) = (hex32(store), hex32(chain_root()));
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        CapsuleWarmer::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(
                dig_download::testkit::mock_providers(1, &content),
            )),
            Arc::new(dig_download::testkit::MockModuleTransport::serving(
                &store_hex, &root_hex, module, 8,
            )),
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::clone(spy) as Arc<dyn AnnounceHolder>,
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::new(crate::tier0_live::NoopModulesEvictor),
        )
    }

    /// Run the node's REAL announce derivation over whatever is on disk under `dir`, exactly as an
    /// announce triggered by any cause does: scan `<cache>/modules`, then map that inventory to the
    /// content ids the DHT records and the opcode-222 flood are both built from.
    ///
    /// Deliberately NOT routed through the warmer: the point under test is what an announce driven by
    /// something else entirely would publish.
    fn announce_set_from_disk(dir: &Path) -> (Vec<crate::CachedCapsule>, Vec<dig_dht::ContentId>) {
        let inventory =
            crate::seams::capsule::list_cached_capsules(&dir.join("cache").join("modules"));
        let ids = crate::dht::inventory_content_ids(&inventory);
        (inventory, ids)
    }

    /// **Proves (dig-node#276):** a relayed capsule is absent from the announce set of a LATER announce
    /// cycle driven by an unrelated cause — while a genuinely-held capsule in the SAME cache is present.
    ///
    /// **Catches the defect a call-scoped suppression leaves open.** Withholding
    /// [`AnnounceHolder::announce_inventory`] on the relayed warm suppresses one CALL. The announce set
    /// is not a product of that call: it is reconciled from `<cache>/modules` by
    /// [`crate::CapsuleStore::cache_list_cached`], and the relayed capsule is written to exactly that
    /// path. So the next announce from ANY other cause — a chain-watch gap-fill, a peer-presence
    /// re-announce, a restart, a local reshare of something else — would advertise this node as a holder
    /// of a stranger's content, which is precisely the amplification primitive the relay must not
    /// reopen. This test drives that later cycle explicitly.
    ///
    /// **Why the fixture is shaped this way, and why the sibling test cannot see this:**
    /// - the announce set is derived FROM DISK rather than from the warm, so a guard placed at the warm
    ///   call site no longer satisfies the assertion — a PLACEMENT change becomes observable, which
    ///   asserting "one call did not happen" can never make it;
    /// - two capsules, one relayed and one honestly held, land in ONE cache directory, so the honest one
    ///   is a truthful control INSIDE the same scan: an empty announce set — a broken scan, a broken id
    ///   mapping, a fixture that cached nothing — fails the control rather than passing the property.
    #[tokio::test]
    async fn a_relayed_capsule_stays_out_of_a_later_unrelated_announce_cycle() {
        let dir = temp_dir("relay-announce-cycle");
        let root_hex = hex32(chain_root());
        let (relay_store_hex, local_store_hex) = (hex32(STORE), hex32(LOCAL_STORE));

        // Both capsules land in the SAME cache, which is what a node that both relays and reshares
        // actually looks like on disk.
        let spy = Arc::new(AnnounceSpy::default());
        let relayed = serving_warmer_for(&dir, &spy, STORE, module_committing(STORE, chain_root()))
            .warm_relayed(&relay_store_hex, &root_hex)
            .await;
        let local = serving_warmer_for(
            &dir,
            &spy,
            LOCAL_STORE,
            module_committing(LOCAL_STORE, chain_root()),
        )
        .warm(&local_store_hex, &root_hex)
        .await;
        assert!(
            matches!(relayed, WarmOutcome::Held { .. })
                && matches!(local, WarmOutcome::Held { .. }),
            "both pulls must genuinely succeed, or the announce set proves nothing"
        );

        let (inventory, announced) = announce_set_from_disk(&dir);

        // The relayed capsule is still CACHED and servable. Suppression withholds the advertisement,
        // never the bytes — serving them is the whole point of relaying.
        assert_eq!(
            inventory.len(),
            2,
            "both capsules are cached and servable; only their provenance differs"
        );
        assert!(
            std::fs::read(
                dir.join("cache")
                    .join("modules")
                    .join(&relay_store_hex)
                    .join(format!("{root_hex}.dig"))
            )
            .is_ok(),
            "the relayed capsule's bytes remain on disk to serve the requestor's windows from"
        );

        // The control, asserted FIRST so an empty announce set can never read as a pass.
        assert!(
            announced.contains(&dig_dht::ContentId::capsule(LOCAL_STORE, chain_root()))
                && announced.contains(&dig_dht::ContentId::store(LOCAL_STORE)),
            "the honestly-held capsule must still be announced, or this fixture proves nothing"
        );

        assert!(
            !announced.contains(&dig_dht::ContentId::capsule(STORE, chain_root())),
            "a later announce cycle must not advertise this node as a holder of a relayed capsule"
        );
        assert!(
            !announced.contains(&dig_dht::ContentId::store(STORE)),
            "nor as a source of the relayed capsule's store at all"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves (dig-node#276):** relaying a generation does not disqualify it forever — a later warm
    /// this node drives for ITSELF promotes the capsule to a genuine holding, and the next announce
    /// cycle picks it up.
    ///
    /// **Catches:** a durable suppression that is write-only. A marker never cleared would exclude from
    /// the flywheel, permanently, every generation any stranger ever routed through this node — a real
    /// cost paid silently, and invisible to the suppression test above, which only ever asks for absence.
    #[tokio::test]
    async fn a_relayed_capsule_becomes_announceable_once_this_node_warms_it_for_itself() {
        let dir = temp_dir("relay-then-local");
        let root_hex = hex32(chain_root());
        let store_hex = hex32(STORE);
        let module = module_committing(STORE, chain_root());
        let spy = Arc::new(AnnounceSpy::default());

        serving_warmer_for(&dir, &spy, STORE, module.clone())
            .warm_relayed(&store_hex, &root_hex)
            .await;
        let (_, suppressed) = announce_set_from_disk(&dir);
        assert!(
            suppressed.is_empty(),
            "the relayed capsule is not announceable before this node claims it"
        );

        // The node now reads that generation for its own sake. The capsule is already on disk, so this
        // is the `AlreadyHeld` path — the one that has to promote provenance rather than shrug.
        let outcome = serving_warmer_for(&dir, &spy, STORE, module)
            .warm(&store_hex, &root_hex)
            .await;
        assert_eq!(outcome, WarmOutcome::AlreadyHeld);

        let (_, announced) = announce_set_from_disk(&dir);
        assert!(
            announced.contains(&dig_dht::ContentId::capsule(STORE, chain_root())),
            "a capsule this node now holds for itself must become announceable"
        );
        assert_eq!(
            spy.calls.load(Ordering::SeqCst),
            1,
            "the promotion announces exactly once — the relayed pull before it announced nothing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A [`ModulesCacheEvictor`](crate::tier0_live::ModulesCacheEvictor) that counts sweeps, so
    /// "the reshare-warm land triggered exactly one sweep" (and "a refusal triggered none") are
    /// assertable properties without a Node.
    #[derive(Default)]
    struct CountingEvictor {
        sweeps: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::tier0_live::ModulesCacheEvictor for CountingEvictor {
        async fn evict_if_needed(&self) {
            self.sweeps.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// **Proves (#2053):** a SUCCESSFUL reshare-warm land runs the tier-aware `<cache>/modules` size-cap
    /// sweep exactly once — the hook that closes the "every on-demand land path bounds the cache"
    /// invariant (#1934/#2041) for the reshare leg. Mirrors `a_successful_pull_is_held...`'s harness so
    /// the sweep is observed on a genuinely-`Held` outcome, not a refusal.
    ///
    /// **Non-vacuous:** the companion assertion below drives a `Refused(PullFailed)` warm through the
    /// SAME wiring and requires ZERO sweeps — so a sweep that fired unconditionally (or never) would
    /// fail one of the two. Removing the `evict_if_needed` call in `warm()` drops the count to 0 here.
    #[tokio::test]
    async fn a_successful_reshare_warm_land_sweeps_the_modules_cache_once() {
        let dir = temp_dir("reshare-sweep-once");
        let (store_hex, root_hex) = (hex32(STORE), hex32(chain_root()));
        let module = module_committing(STORE, chain_root());
        let content = dig_download::module_content_id(&store_hex, &root_hex)
            .expect("canonical ids yield a content id");
        let locator = Arc::new(dig_download::testkit::MockProviderLocator::fixed(
            dig_download::testkit::mock_providers(1, &content),
        ));
        let transport = Arc::new(dig_download::testkit::MockModuleTransport::serving(
            &store_hex,
            &root_hex,
            module.clone(),
            8,
        ));
        let evictor = Arc::new(CountingEvictor::default());
        let warmer = CapsuleWarmer::new(
            locator,
            transport,
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::InMemoryStateStore::new()),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::clone(&evictor) as Arc<dyn crate::tier0_live::ModulesCacheEvictor>,
        );

        let outcome = warmer.warm(&store_hex, &root_hex).await;

        assert!(
            matches!(outcome, WarmOutcome::Held { .. }),
            "the harness must actually land the capsule, or the sweep assertion proves nothing"
        );
        assert_eq!(
            evictor.sweeps.load(Ordering::SeqCst),
            1,
            "a successful reshare-warm land must run the modules-cache size-cap sweep exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves (#2053):** a REFUSED reshare warm sweeps NOTHING — a pull that wrote no module into the
    /// cache has nothing to bound, so the sweep is gated on the `Held` outcome, never fired blindly.
    #[tokio::test]
    async fn a_refused_reshare_warm_does_not_sweep_the_modules_cache() {
        let dir = temp_dir("reshare-sweep-none");
        let evictor = Arc::new(CountingEvictor::default());
        let warmer = CapsuleWarmer::new(
            Arc::new(NoHolders),
            Arc::new(UnusedTransport),
            Arc::new(crate::seams::dig_peer::NoPullState),
            Arc::new(dig_download::FileStateStore::new(dir.join("state"))),
            Arc::new(ConfirmingResolver),
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            Arc::new(AnnounceSpy::default()),
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
            Arc::clone(&evictor) as Arc<dyn crate::tier0_live::ModulesCacheEvictor>,
        );

        let outcome = warmer.warm(&hex32(STORE), &hex32(chain_root())).await;

        assert!(matches!(
            outcome,
            WarmOutcome::Refused(WarmFailure::PullFailed { .. })
        ));
        assert_eq!(
            evictor.sweeps.load(Ordering::SeqCst),
            0,
            "a refused warm landed nothing, so it must not run the modules-cache sweep"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** with no chain anchor the pull never STARTS — the node does not even attempt to fetch
    /// a generation it could not verify, and announces nothing.
    /// **Catches:** pulling first and hoping to verify later, which is how a peer-supplied root ends up
    /// being the only available anchor.
    #[tokio::test]
    async fn without_a_chain_anchor_the_pull_never_starts() {
        let dir = temp_dir("no-anchor");
        let spy = Arc::new(AnnounceSpy::default());
        let warmer = warmer_with(Arc::new(UnreachableChain), Arc::clone(&spy), &dir);

        let outcome = warmer.warm(&hex32(STORE), &hex32(chain_root())).await;

        assert_eq!(outcome, WarmOutcome::Refused(WarmFailure::NoChainAnchor));
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a generation whose root is NOT the chain's anchored root is refused before any pull —
    /// so a peer cannot induce a pull of a generation it made up.
    #[tokio::test]
    async fn a_generation_the_chain_does_not_confirm_is_refused() {
        let dir = temp_dir("wrong-gen");
        let spy = Arc::new(AnnounceSpy::default());
        let warmer = warmer_with(Arc::new(ConfirmingResolver), Arc::clone(&spy), &dir);

        // The chain says CHAIN_ROOT; this asks to warm a different generation.
        let outcome = warmer.warm(&hex32(STORE), &hex32([0xc3; 32])).await;

        assert_eq!(outcome, WarmOutcome::Refused(WarmFailure::NoChainAnchor));
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a non-canonical id is refused rather than reaching the network.
    #[tokio::test]
    async fn a_non_canonical_id_is_refused() {
        let dir = temp_dir("bad-id");
        let spy = Arc::new(AnnounceSpy::default());
        let warmer = warmer_with(Arc::new(ConfirmingResolver), Arc::clone(&spy), &dir);
        assert_eq!(
            warmer.warm("not-an-id", &hex32(chain_root())).await,
            WarmOutcome::Refused(WarmFailure::NoChainAnchor)
        );
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- one warm per generation -------------------------------------------------------------------

    /// **Proves:** the registry admits one claim per generation and releases it on drop, so a burst of
    /// reads across a capsule's resources cannot start N concurrent pulls of the same module — while a
    /// finished (or panicking) warm still leaves the generation warmable again.
    #[test]
    fn one_warm_per_generation_at_a_time() {
        let registry = Arc::new(WarmRegistry::new());
        let first = registry.claim("s:r".into()).expect("first claim granted");
        assert!(registry.is_warming("s:r"));
        assert!(
            registry.claim("s:r".into()).is_none(),
            "a second warm of the same generation is refused"
        );
        assert!(
            registry.claim("s:other".into()).is_some(),
            "a different generation is unaffected"
        );
        drop(first);
        assert!(!registry.is_warming("s:r"));
        assert!(
            registry.claim("s:r".into()).is_some(),
            "the generation is warmable again once the claim is released"
        );
    }

    /// **Proves (dig-node#333 review, finding 3):** a RELAYED warm and this node's OWN warm draw from
    /// the SAME bounded pool of concurrent-warm slots, so a relay started for a stranger can deny a
    /// slot to a local read.
    ///
    /// **Why this is worth a test rather than a comment:** the relay pull changed from awaited to
    /// SPAWNED, so it now outlives the request that asked for it — a peer that gives up leaves the
    /// slot held. The behaviour is bounded and opt-in and is not a hole, but "relaying for strangers
    /// can starve your own warms" is a property an operator enabling the leg needs to be able to
    /// discover, and an undocumented, untested property is one that quietly changes.
    ///
    /// **Fixture design:** the cap is filled by RELAY-shaped claims and the local warm is the one
    /// refused, which is the direction that matters. Asserting the reverse — that a local warm can
    /// deny a relay — would be satisfied by any shared cap and would not distinguish the two pools
    /// being one from the two pools merely both existing.
    #[test]
    fn a_relayed_warm_and_a_local_warm_compete_for_the_same_slots() {
        let registry = Arc::new(WarmRegistry::new());

        // Every slot taken by capsules a STRANGER asked this node to relay.
        let relayed: Vec<_> = (0..DEFAULT_MAX_CONCURRENT_WARMS)
            .map(|n| {
                registry
                    .claim(format!("relayed:{n}"))
                    .expect("a relay claim within the cap is granted")
            })
            .collect();

        assert!(
            registry.claim("local:mine".into()).is_none(),
            "this node's OWN warm was refused a slot because relays hold them all — the two share              one cap, which is the cost of running the relay leg"
        );

        // A finished relay hands the slot back; nothing about the claim is relay-specific.
        drop(relayed.into_iter().next().expect("at least one claim"));
        assert!(
            registry.claim("local:mine".into()).is_some(),
            "the control: the local warm must succeed once a relay slot frees, or the refusal above              proves only that the registry was broken"
        );
    }

    /// **Proves:** breadth across DISTINCT generations is capped — the (N+1)th distinct generation is
    /// SKIPPED, not queued, once `max_concurrent` are already in flight; a slot freed by a finished warm
    /// makes the registry warmable again.
    /// **Catches:** K distinct capsule reads starting K concurrent whole-module pulls with no bound
    /// (#1615/G3) — reachable from ordinary read breadth, no attacker required.
    #[test]
    fn distinct_generations_are_capped_and_skip_rather_than_queue() {
        let registry = Arc::new(WarmRegistry::with_limit(2));

        let first = registry.claim("s:1".into()).expect("first of two admitted");
        let second = registry
            .claim("s:2".into())
            .expect("second of two admitted");
        assert!(
            registry.claim("s:3".into()).is_none(),
            "a third DISTINCT generation is skipped once the cap is reached"
        );
        // Skipped means gone, not waiting: releasing a slot does not retroactively grant the skipped
        // claim — the caller must ask again (which the read path naturally does on its next read).
        assert!(!registry.is_warming("s:3"));

        drop(first);
        assert!(
            registry.claim("s:3".into()).is_some(),
            "a freed slot admits a fresh claim"
        );
        drop(second);
    }
}
