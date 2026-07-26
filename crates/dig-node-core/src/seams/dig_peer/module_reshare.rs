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
//!   <cache>/modules/<store>/<root>.module                 CACHED  ==  ANNOUNCED AS HOLDER
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

use super::module_anchor::{sha256, ChainAnchoredModuleVerifier};

/// The set of `(store, root)` generations a warm pull is currently in flight for.
///
/// A capsule read typically fetches several resources in quick succession, each of which would
/// otherwise trigger its own whole-module pull of the SAME module — N concurrent pulls of one capsule,
/// racing each other into the same staging file. This registry makes the warm idempotent while it runs.
#[derive(Debug, Default)]
pub struct WarmRegistry {
    in_flight: Mutex<HashSet<String>>,
}

impl WarmRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        WarmRegistry::default()
    }

    /// Claim `key` for a warm pull, or `None` if one is already in flight for it.
    ///
    /// The claim is released when the returned guard drops — including on panic, so a panicking pull
    /// cannot permanently block a generation from ever being warmed again.
    fn claim(self: &Arc<Self>, key: String) -> Option<WarmClaim> {
        let mut guard = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !guard.insert(key.clone()) {
            return None;
        }
        Some(WarmClaim {
            registry: Arc::clone(self),
            key,
        })
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
struct WarmClaim {
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
    PullFailed,
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
    /// A warm for this generation was already in flight; this call did nothing.
    AlreadyWarming,
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
    /// The node's cache dir. The final hop writes `<cache>/modules/<store>/<root>.module`.
    pub cache_dir: PathBuf,
}

impl WarmPaths {
    /// The staging target for `(store, root)` — the path dig-download's `FileSink` finalizes onto,
    /// having staged in `<that>.download.tmp`.
    fn staged_module(&self, store_hex: &str, root_hex: &str) -> PathBuf {
        self.staging_dir
            .join("modules")
            .join(format!("{store_hex}-{root_hex}.dig"))
    }

    /// The cache path whose EXISTENCE makes this node a holder (matches `crate::module_path`).
    fn cached_module(&self, store_hex: &str, root_hex: &str) -> PathBuf {
        self.cache_dir
            .join("modules")
            .join(store_hex)
            .join(format!("{root_hex}.module"))
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
    let tmp = cached.with_extension("module.warm.tmp");
    std::fs::write(&tmp, &bytes).map_err(|_| WarmFailure::CacheWriteFailed)?;
    std::fs::rename(&tmp, cached).map_err(|_| {
        let _ = std::fs::remove_file(&tmp);
        WarmFailure::CacheWriteFailed
    })?;
    Ok(bytes.len() as u64)
}

/// Discard a warm's staging artifacts, so a failed pull leaves nothing behind that a later run (or a
/// GC sweep) could mistake for progress.
fn discard_staging(staged: &Path) {
    let _ = std::fs::remove_file(staged);
    let _ = std::fs::remove_file(dig_download::staging_path_for(staged));
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
    pub fn new(
        locator: Arc<dyn dig_download::ProviderLocator>,
        transport: Arc<dyn dig_download::ModuleTransport>,
        state_store: Arc<dyn dig_download::StateStore>,
        anchor_resolver: Arc<dyn crate::shared::AnchoredRootResolver>,
        paths: WarmPaths,
        announce: Arc<dyn AnnounceHolder>,
        registry: Arc<WarmRegistry>,
        config: dig_download::ModuleDownloadConfig,
    ) -> Arc<Self> {
        Arc::new(CapsuleWarmer {
            locator,
            transport,
            state_store,
            anchor_resolver,
            paths,
            announce,
            registry,
            config,
        })
    }

    /// Pull the whole capsule for `(store_hex, root_hex)`, cache it, and announce this node as a
    /// holder — the full reshare step, awaited.
    ///
    /// Callers on the read path use [`spawn_capsule_warm`] instead; this is the awaitable core so the
    /// behaviour is testable without a background task.
    pub async fn warm(self: &Arc<Self>, store_hex: &str, root_hex: &str) -> WarmOutcome {
        let key = format!("{store_hex}:{root_hex}");
        let Some(_claim) = self.registry.claim(key.clone()) else {
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
        let staged = self.paths.staged_module(store_hex, root_hex);
        let sink = dig_download::FileSink::new(&staged);
        let downloader = dig_download::ModuleDownloader::new(
            Arc::clone(&self.locator),
            Arc::clone(&self.transport),
            Arc::new(verifier.clone()),
            Arc::clone(&self.state_store),
            self.config.clone(),
        );

        let pulled = downloader.download(store_hex, root_hex, &sink).await;

        // 3. ONLY `Ok` may lead to a holder claim. Not finalize-observed, not partial staging, not an
        //    `Err` that happened to leave bytes behind.
        let Ok(bytes) = pulled else {
            discard_staging(&staged);
            tracing::info!(
                store = %super::serve_log::SafeId::new(store_hex),
                root = %super::serve_log::SafeId::new(root_hex),
                outcome = "refused",
                reason = "pull failed",
                "capsule warm: pull did not complete; this node is NOT a holder"
            );
            return WarmOutcome::Refused(WarmFailure::PullFailed);
        };

        // 4. Promote into the cache, re-proving the artifact is the admitted one, THEN announce.
        let cached = self.paths.cached_module(store_hex, root_hex);
        match promote_into_cache(&staged, &cached, &verifier) {
            Ok(promoted) => {
                discard_staging(&staged);
                self.announce.announce_inventory().await;
                tracing::info!(
                    store = %super::serve_log::SafeId::new(store_hex),
                    root = %super::serve_log::SafeId::new(root_hex),
                    outcome = "held",
                    bytes = promoted,
                    "capsule warm: whole capsule verified + cached; announced as a holder"
                );
                WarmOutcome::Held { bytes: promoted }
            }
            Err(failure) => {
                discard_staging(&staged);
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
    use digstore_core::datasection::{encode_blob, SectionId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const STORE: [u8; 32] = [0xa1; 32];
    const CHAIN_ROOT: [u8; 32] = [0xb2; 32];

    fn hex32(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A `.dig`-shaped module committing `store` + `root`.
    fn module_committing(store: [u8; 32], root: [u8; 32]) -> Vec<u8> {
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
        ])
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dig-node-warm-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
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

    /// **Proves:** a staged artifact that IS the admitted one is promoted into the cache.
    #[test]
    fn promotes_the_artifact_the_gate_admitted() {
        let dir = temp_dir("promote-ok");
        let module = module_committing(STORE, CHAIN_ROOT);
        let staged = dir.join("staged.dig");
        std::fs::write(&staged, &module).unwrap();

        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(CHAIN_ROOT));
        assert!(dig_download::ModuleAnchorVerifier::verify_module_anchor(
            &verifier,
            &module,
            &hex32(STORE),
            &hex32(CHAIN_ROOT)
        ));

        let cached = dir.join("cached.module");
        assert_eq!(
            promote_into_cache(&staged, &cached, &verifier),
            Ok(module.len() as u64)
        );
        assert_eq!(std::fs::read(&cached).unwrap(), module);
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
        let module = module_committing(STORE, CHAIN_ROOT);
        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(CHAIN_ROOT));
        assert!(dig_download::ModuleAnchorVerifier::verify_module_anchor(
            &verifier,
            &module,
            &hex32(STORE),
            &hex32(CHAIN_ROOT)
        ));

        // The gate admitted `module`; what is on disk is something else (one flipped byte, and a
        // trailing tail — both invisible to a caller that only checks the Ok).
        let staged = dir.join("staged.dig");
        let mut tampered = module.clone();
        tampered.extend_from_slice(b"trailing garbage");
        std::fs::write(&staged, &tampered).unwrap();

        let cached = dir.join("cached.module");
        assert_eq!(
            promote_into_cache(&staged, &cached, &verifier),
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
        std::fs::write(&staged, module_committing(STORE, CHAIN_ROOT)).unwrap();
        let verifier =
            ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(CHAIN_ROOT));

        let cached = dir.join("cached.module");
        assert_eq!(
            promote_into_cache(&staged, &cached, &verifier),
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
            Ok(Some(Bytes32(CHAIN_ROOT)))
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
            Arc::new(dig_download::FileStateStore::new(dir.join("state"))),
            resolver,
            WarmPaths {
                staging_dir: dir.join("staging"),
                cache_dir: dir.join("cache"),
            },
            announce,
            Arc::new(WarmRegistry::new()),
            dig_download::ModuleDownloadConfig::default(),
        )
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

        let outcome = warmer.warm(&hex32(STORE), &hex32(CHAIN_ROOT)).await;

        assert_eq!(outcome, WarmOutcome::Refused(WarmFailure::PullFailed));
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

    /// **Proves:** with no chain anchor the pull never STARTS — the node does not even attempt to fetch
    /// a generation it could not verify, and announces nothing.
    /// **Catches:** pulling first and hoping to verify later, which is how a peer-supplied root ends up
    /// being the only available anchor.
    #[tokio::test]
    async fn without_a_chain_anchor_the_pull_never_starts() {
        let dir = temp_dir("no-anchor");
        let spy = Arc::new(AnnounceSpy::default());
        let warmer = warmer_with(Arc::new(UnreachableChain), Arc::clone(&spy), &dir);

        let outcome = warmer.warm(&hex32(STORE), &hex32(CHAIN_ROOT)).await;

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
            warmer.warm("not-an-id", &hex32(CHAIN_ROOT)).await,
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
}
