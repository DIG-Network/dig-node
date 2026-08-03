//! Seam 6's public surface (#1285/#1303) — the on-disk capsule cache operations the RPC/control
//! surface (`dig-node-service`'s `control.rs`, the in-process `dig-wallet` FFI surface, the L7 peer
//! RPC inventory answers) and the chain-watch gap-filler drive on [`Node`].
//!
//! `CapsuleStore` is implemented by [`Node`] with its EXISTING method bodies (carved unchanged from
//! `lib.rs`/`download.rs`, #1285 W1b-4) — a behaviour-preserving trait extraction, not a new
//! implementation. `async_trait`-boxed (matching the other seam traits) so it stays dyn-compatible
//! for the future `Arc<dyn CapsuleStore>` handle (W1c).
//!
//! This is also where the W1b-2-deferred self-reference bring-up hooks (`set_self_ref`/`arc_self`)
//! land, per the locked plan's tangle (b): they exist ONLY to let `&self` capsule read handlers
//! (`maybe_backfill_capsule`) spawn an owned-`Arc` background pull — genuinely a capsule-store
//! concern, not a peer-network one. They stay a plain `Weak<Node>`/`Arc<Node>` pair for this
//! behaviour-preserving pass (full struct decomposition into `Arc<dyn CapsuleStore>` is W1c's job).

use std::sync::{Arc, Weak};

use digstore_core::Bytes32;

use crate::{module_exists, CachedCapsule, Node, PeerNetwork};

/// Seam 6 (capsule management) — the node's on-disk `.dig` capsule cache: list/remove/fetch a held
/// capsule, gap-fill a missing chain-confirmed generation, and the self-reference plumbing that lets
/// `&self` read handlers spawn an owned background backfill.
#[async_trait::async_trait]
pub trait CapsuleStore: Send + Sync {
    /// List every cached capsule (`storeId:rootHash`) with its on-disk size and
    /// last-used time. Walks `<cache>/modules/<storeId_hex>/<root_hex>.dig`
    /// (the same layout `module_path`/`serve_local`/`sync_module_from` use),
    /// reusing the directory-enumerate pattern from [`cache_used_bytes`](crate::cache_used_bytes) and
    /// [`Node::evict_if_needed`]. `last_used_unix_ms` is the file mtime (the LRU
    /// recency stamp bumped by [`touch`] on every local serve), in Unix epoch ms.
    async fn cache_list_cached(&self) -> Vec<CachedCapsule>;

    /// Remove one cached capsule's module by `(store_id_hex, root_hex)`. Returns
    /// `Ok(true)` if a module was unlinked, `Ok(false)` if it was already absent
    /// (idempotent), or `Err` for invalid input.
    ///
    /// PATH-TRAVERSAL DEFENSE: the hex inputs are validated 64-hex (mirroring the
    /// `response_key`/`sync_eligible` sanitization), then the resolved path is
    /// canonicalized and asserted to live UNDER the cache dir before any unlink —
    /// so a crafted `store_id`/`root` can never delete a file outside the cache.
    /// Holds the existing `cache_lock` for the unlink so it can't race eviction.
    /// (Async because that lock is a `tokio::sync::Mutex`, acquired with `.await`.)
    async fn cache_remove_cached(&self, store_id_hex: &str, root_hex: &str)
        -> Result<bool, String>;

    /// Fetch and cache one capsule on demand over the §21 authenticated
    /// whole-store sync path (the same `sync_module_from` / `DigClient::clone_store`
    /// the local-first miss path uses, signed with the startup `identity_seed`).
    /// Returns `(size_bytes, served_root_hex)` on success.
    ///
    /// If the capsule is already cached it returns its size without re-downloading
    /// (the RPC reports `already_cached`). The cache write itself happens inside
    /// `sync_module_from`, which already serializes via the module path; this also
    /// holds the `cache_lock` around the call so concurrent on-demand fetches of
    /// the same capsule don't race each other.
    async fn cache_fetch_and_cache(
        &self,
        store_id_hex: &str,
        root_hex: &str,
    ) -> Result<(u64, String), String>;

    /// Sync a whole store BY STORE ID, with no caller-supplied root: resolve the store's
    /// CHAIN-ANCHORED tip and cache that generation. Returns `(size_bytes, root_hex)`.
    ///
    /// The root comes from the chain, never from the serving upstream (#1886). An upstream
    /// asked for "latest" would be choosing which generation this node caches, reshares, and
    /// announces itself as a holder of; the chain is the only authority for a store's tip.
    ///
    /// This is the entry point a "sync this store" request needs — until it existed, the only
    /// way in required the caller to already know a concrete root, so a control-plane trigger
    /// by store id had nothing to call.
    ///
    /// # Errors
    /// A non-64-hex store id, a store with no confirmed generation on chain, an unreachable
    /// chain resolver, or the underlying download failure verbatim.
    async fn sync_whole_store(&self, store_id_hex: &str) -> Result<(u64, String), String>;

    /// GAP-FILL one missing generation (SPEC §14.3): pull the whole `.dig` module for
    /// `(store_id, root)` down from other nodes, verify it against the chain-anchored root, land it in
    /// the local cache, and (best-effort) refresh the DHT provider records so peers immediately find
    /// this node as a NEW holder of the just-synced capsule (§14.1). Idempotent — an already-held
    /// generation is a cheap success with no network.
    ///
    /// The pull reuses the authenticated whole-store sync ([`Self::cache_fetch_and_cache`] →
    /// `sync_module_from`), which lands the module keyed by capsule `(store, root)`. The
    /// VERIFICATION INVARIANT (SPEC §14.3) is upheld at every SERVE: a gap-filled module is never served
    /// as current unless its root equals the chain-anchored tip (the read-path pin, §14.4), so a
    /// tampered or wrong-generation pull can never be served — the same guarantee whether the module
    /// arrived via a client read, a §21 sync, or this proactive gap-fill.
    ///
    /// `root` is passed as [`Bytes32`] (the chain-anchored tip the watcher resolved), so gap-fill
    /// always targets a chain-confirmed generation — never a caller-chosen root.
    async fn gap_fill_generation(&self, store_id: [u8; 32], root: Bytes32) -> Result<(), String>;

    /// Background CAPSULE BACKFILL (SPEC §5.6): when a resource read for `(store_hex, root_hex)` is
    /// being satisfied FROM ANOTHER NODE (a redirect or a fetch-through miss), also pull the WHOLE
    /// `.dig` capsule for that generation in the background and cache it, so the NEXT read of this
    /// store is served locally. Configurable (`DIG_NODE_BACKFILL_ON_MISS`, default ON).
    ///
    /// Fire-and-forget: it spawns a detached task and returns immediately so the current read is never
    /// delayed. It is a NO-OP when: backfill is disabled; there is no P2P content engine (the
    /// in-process FFI consumer — it has no upstream/peer network to pull a whole capsule from); the
    /// capsule is already held locally; or a backfill for this exact capsule is already in flight
    /// (deduped via the shared `capsule_acquisition` gate — one `WarmRegistry` both this §21 backfill
    /// and the P2P reshare leg claim — so a burst of resource reads for the same not-yet-held store,
    /// across either acquisition transport, triggers ONE whole-`.dig` pull, not one per read). The pull reuses
    /// [`Self::gap_fill_generation`] — the authenticated §21 whole-store sync, chain-anchored-root
    /// pinned + DHT-announced — so a backfilled capsule is verified exactly like every other cached
    /// generation.
    ///
    /// `origin` is the SAME gate the #1576 reshare leg uses and for the SAME reason: a remote peer's
    /// `dig.fetchRange`/`dig.getContent` miss must never trigger a whole-capsule pull + cache
    /// promotion + DHT holder-announce of a capsule THAT PEER named — this is a no-op unless
    /// `origin == ReadOrigin::Local`.
    fn maybe_backfill_capsule(
        &self,
        store_hex: &str,
        root_hex: &str,
        origin: crate::download::ReadOrigin,
    );

    /// Install the WEAK self-reference (the standalone peer-network bring-up calls this once with the
    /// `Arc<Node>` it holds). Enables `&self` read handlers to spawn owned-`Arc` background tasks — the
    /// capsule backfill (§14.3). Idempotent; never set on the FFI path.
    fn set_self_ref(&self, weak: Weak<Node>);

    /// Upgrade the weak self-reference to an owned `Arc<Node>`, if the standalone bring-up installed
    /// one and the node is still alive. `None` on the FFI path / before bring-up / during teardown.
    fn arc_self(&self) -> Option<Arc<Node>>;
}

#[async_trait::async_trait]
impl CapsuleStore for Node {
    async fn cache_list_cached(&self) -> Vec<CachedCapsule> {
        let modules_root = self.cache_dir.join("modules");
        let mut out = Vec::new();
        // Outer level: one directory per store id (hex). Inner: `<root>.dig` (or a legacy `<root>.module`).
        let Ok(stores) = std::fs::read_dir(&modules_root) else {
            return out; // no modules cached yet
        };
        for store_entry in stores.flatten() {
            if !store_entry.path().is_dir() {
                continue;
            }
            let Some(store_hex) = store_entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(modules) = std::fs::read_dir(store_entry.path()) else {
                continue;
            };
            for m in modules.flatten() {
                let path = m.path();
                // A capsule module is `<root_hex>.dig` (or a legacy `<root_hex>.module` a prior binary
                // wrote — #1896); either names a held capsule, so stripping BOTH suffixes from one
                // authority is what keeps a legacy holder discoverable through the upgrade.
                let Some(root_hex) = path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .and_then(crate::capsule_key::cached_root_stem)
                    .map(str::to_string)
                else {
                    continue;
                };
                let Ok(md) = m.metadata() else { continue };
                let last_used_unix_ms = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                out.push(CachedCapsule {
                    store_id: store_hex.clone(),
                    root: root_hex,
                    size_bytes: md.len(),
                    last_used_unix_ms,
                });
            }
        }
        out
    }

    async fn cache_remove_cached(
        &self,
        store_id_hex: &str,
        root_hex: &str,
    ) -> Result<bool, String> {
        // The rejection message names WHICH component was bad but never ECHOES it: the caller supplied
        // these bytes, and this error string is logged (#1603/#1609). The caller already knows what it
        // sent, so quoting it back adds no diagnostic value and would hand an attacker the log.
        let Some(capsule) = crate::CapsuleKey::parse(store_id_hex, root_hex) else {
            return Err("invalid capsule key: store_id and root must each be 64-hex".to_string());
        };
        // Remove whichever artifact is on disk — the current `.dig` or a legacy `.module` (#1896) — so
        // a removal on a not-yet-migrated cache still clears the holder claim.
        let path = capsule.resolve_cached_path(&self.cache_dir);

        let _guard = self.cache_lock.lock().await;
        if !path.exists() {
            return Ok(false); // nothing to remove — idempotent no-op
        }
        // Canonicalize and confirm the target is contained by the cache dir. With
        // 64-hex inputs this always holds; the check is defense-in-depth so the
        // unlink can never reach outside the cache even if the layout changes.
        let canon = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
        let cache_canon = std::fs::canonicalize(&self.cache_dir).map_err(|e| e.to_string())?;
        if !canon.starts_with(&cache_canon) {
            return Err("refusing to remove a path outside the cache dir".to_string());
        }
        std::fs::remove_file(&canon).map_err(|e| e.to_string())?;
        // Drop any in-memory decoded content for this capsule so a removed module can never still be
        // served from the content cache (audit #179).
        self.invalidate_content_cache(store_id_hex, root_hex);
        Ok(true)
    }

    async fn cache_fetch_and_cache(
        &self,
        store_id_hex: &str,
        root_hex: &str,
    ) -> Result<(u64, String), String> {
        // Validated once, up front: a non-canonical key can name no capsule to report and no capsule to
        // fetch, so it is refused before either the stat or the network hop (#1599).
        let capsule = crate::CapsuleKey::parse(store_id_hex, root_hex).ok_or_else(|| {
            "invalid capsule key: store_id and root must each be 64-hex".to_string()
        })?;
        // Already cached → report its size, no network (tolerating a legacy `.module`, #1896).
        if let Ok(md) = std::fs::metadata(capsule.resolve_cached_path(&self.cache_dir)) {
            return Ok((md.len(), root_hex.to_string()));
        }
        // Serialize on-demand writes so two fetches of the same capsule don't race.
        let _guard = self.cache_lock.lock().await;
        // The module lands under its SERVED root, which may differ from the requested one if
        // the remote head advanced mid-sync, so we read the file back to report size + confirm
        // THIS capsule is now present.
        let sync = self
            .sync_module_from(&self.upstream, store_id_hex, root_hex)
            .await;
        // A fresh land is written as `.dig`; resolve tolerates a legacy `.module` already on disk.
        let path = capsule.resolve_cached_path(&self.cache_dir);
        match std::fs::metadata(&path) {
            Ok(md) => {
                // A capsule just entered this node's served set at runtime. Landing a capsule MUST make
                // this node a DISCOVERABLE holder — the reshare/flywheel invariant (#1423/#1425): every
                // path that lands a capsule (a hosted pin, the read-side backfill-cache, gap-fill, the
                // CacheFetchAndCache RPC) flows through here, so announcing ONCE at this single site
                // makes them all discoverable. We only reach this point on a FRESH land (an
                // already-cached capsule returned at the top before any network), so the announce fires
                // exactly once per newly-held capsule — no double-announce. Best-effort + a no-op on the
                // FFI path (no refresher installed).
                self.refresh_dht_inventory().await;
                // A capsule just grew `<cache>/modules`. Run the tier-aware size-cap sweep so every
                // land path (gap-fill, §21 backfill, this RPC) keeps whole-capsule storage bounded at
                // the cache cap — not only the tier-0 precache loop (#1934 disk-exhaustion fix). The
                // `_guard` above already holds `cache_lock`, so call the LOCKED core directly (the
                // `_if_needed` wrapper re-takes `cache_lock` and would deadlock).
                self.evict_modules_locked();
                Ok((md.len(), root_hex.to_string()))
            }
            // No file on disk. The sync's OWN outcome says why — never a list of causes that
            // were not checked. A guess-list here sent #1886's investigation at authorization
            // for days while the upstream had been answering a plain HTTP 400.
            Err(_) => match sync {
                Ok(served) => Err(format!(
                    "capsule {store_id_hex}:{root_hex} not cached: the upstream served root {} \
                     instead (its head moved)",
                    served.to_hex()
                )),
                Err(reason) => Err(format!(
                    "could not fetch capsule {store_id_hex}:{root_hex}: {reason}"
                )),
            },
        }
    }

    async fn sync_whole_store(&self, store_id_hex: &str) -> Result<(u64, String), String> {
        let store_id =
            crate::dht::hex64(store_id_hex).ok_or_else(|| "store_id must be 64-hex".to_string())?;
        let root = crate::ChainSource::anchored_root_resolver_arc(self)
            .anchored_root(&store_id)
            .await
            .map_err(|e| format!("could not resolve the chain-anchored root: {e}"))?
            .ok_or_else(|| "the store has no chain-confirmed generation to sync".to_string())?;
        self.cache_fetch_and_cache(store_id_hex, &root.to_hex())
            .await
    }

    async fn gap_fill_generation(&self, store_id: [u8; 32], root: Bytes32) -> Result<(), String> {
        let store_hex = hex::encode(store_id);
        let root_hex = root.to_hex();
        // Already held → nothing to pull (idempotent).
        if module_exists(&self.cache_dir, &store_hex, &root_hex) {
            return Ok(());
        }
        // Pull + cache the whole module under (store, root) via the authenticated §21 whole-store sync.
        // `cache_fetch_and_cache` serializes concurrent pulls of the same capsule and reports the
        // failure reason (no identity / not authorized / served root differs) on error.
        self.cache_fetch_and_cache(&store_hex, &root_hex).await?;

        // Confirm the generation actually landed (a sync whose served root differed leaves it absent).
        // The DHT re-announce that makes this node a discoverable holder (§14.1) already fired inside
        // `cache_fetch_and_cache` on the fresh land above — the single centralized announce site.
        if !module_exists(&self.cache_dir, &store_hex, &root_hex) {
            return Err(format!(
                "gap-fill for {store_hex}:{root_hex} pulled a module but not at the confirmed root"
            ));
        }
        Ok(())
    }

    fn maybe_backfill_capsule(
        &self,
        store_hex: &str,
        root_hex: &str,
        origin: crate::download::ReadOrigin,
    ) {
        // ORIGIN GATE FIRST (checked before the config gate deliberately): a remote peer must never
        // be able to make this node pull, cache, and DHT-announce a capsule of the PEER'S choosing —
        // the exact primitive the #1576 reshare leg's own `ReadOrigin` gate exists to close. This is
        // the sibling call site that gate had NOT yet reached. The inbound-demand trigger (#1990)
        // reaches the SHARED pull body ([`Node::spawn_capsule_backfill`]) through its OWN opt-in gate,
        // never through this origin-gated fetch-side entry.
        if origin != crate::download::ReadOrigin::Local {
            return;
        }
        self.spawn_capsule_backfill(store_hex, root_hex);
    }

    fn set_self_ref(&self, weak: Weak<Node>) {
        let _ = self.self_ref.set(weak);
    }

    fn arc_self(&self) -> Option<Arc<Node>> {
        self.self_ref.get().and_then(Weak::upgrade)
    }
}

impl Node {
    /// The SHARED whole-`.dig` backfill pull body: spawn a detached, single-flighted, chain-anchored
    /// pull of the `(store_hex, root_hex)` capsule so a subsequent read is served locally. This is the
    /// ONE source of truth for "warm the whole capsule" — reached by BOTH the fetch-side
    /// [`CapsuleStore::maybe_backfill_capsule`] (after its `ReadOrigin::Local` gate) and the
    /// inbound-demand trigger [`Node::note_inbound_demand`] (after its opt-in config gate), so the two
    /// tier-1 caching triggers can never drift in how they pull, dedupe, verify, or announce.
    ///
    /// The CALLER owns the "should we pull at all?" policy (origin gate / opt-in gate); this body owns
    /// only the mechanics and their own always-required guards:
    /// - **config + peer-network** — the `DIG_NODE_BACKFILL_ON_MISS` kill switch and the presence of a
    ///   P2P content engine to pull from (a no-op on the FFI/consumer path, which has neither);
    /// - **owned self-ref** — an `Arc<Node>` to spawn the detached task (installed by the standalone
    ///   bring-up; `None` on the FFI path or during teardown);
    /// - **concrete (store, root)** — a rootless/`"latest"`/malformed key names no capsule and is
    ///   skipped;
    /// - **already-held** — a held capsule needs no warm-up;
    /// - **single-flight** — the SHARED `(store, root)` acquisition gate (#1614) both this leg and the
    ///   #1576 reshare warm claim, so a burst of reads across either leg starts exactly ONE pull.
    pub(crate) fn spawn_capsule_backfill(&self, store_hex: &str, root_hex: &str) {
        // Config gate (default on) + only where a peer network / upstream exists to pull from.
        if !crate::download::backfill_on_miss_enabled() || self.p2p_content().is_none() {
            return;
        }
        // Need an owned `Arc<Node>` to spawn the detached pull. Installed by the standalone
        // peer-network bring-up; `None` on the FFI path (which also has no p2p_content, so we already
        // returned above) or during teardown.
        let Some(node) = self.arc_self() else {
            return;
        };
        // Need a concrete, valid (store, root). `hex64` validates AND decodes; a rootless/`"latest"`
        // read (no concrete capsule) or a malformed value yields `None` and is skipped — the read
        // path resolves the tip separately.
        let (Some(store_id), Some(root_bytes)) =
            (crate::dht::hex64(store_hex), crate::dht::hex64(root_hex))
        else {
            return;
        };
        // Already held → nothing to warm up.
        if crate::module_exists(self.cache_dir_path(), store_hex, root_hex) {
            return;
        }
        let key = format!("{store_hex}:{root_hex}");
        // Single-flight against the SHARED acquisition gate (#1614): this §21 backfill and the #1576
        // reshare warm are two transports for the SAME capsule, so they claim ONE registry. If the
        // other leg (or a prior read on this leg) already claimed this capsule, do nothing — a burst of
        // resource reads for the same not-yet-held store triggers exactly ONE whole-capsule pull across
        // BOTH legs. The gates ABOVE (config, p2p_content, already-held) all run BEFORE this claim, so a
        // gated-out read never consumes a concurrency slot (#1576/#1654).
        let Some(claim) = self.capsule_acquisition.clone().claim(key.clone()) else {
            return; // an acquisition for this capsule is already in flight on one of the two legs
        };
        let root = Bytes32(root_bytes);
        tokio::spawn(async move {
            // The claim guard is MOVED into the task so the single-flight slot is held for the whole
            // pull and released on completion (or drop, incl. panic), never before the pull spawns.
            let _claim = claim;
            // OPERATOR-VISIBLE at the default level, both ways (#1886): landing a capsule is
            // the moment this node becomes a holder and the content-replication flywheel turns,
            // and failing to land one is the moment it silently does not. At `debug!` a broken
            // flywheel looked exactly like a working one from any log a user would run.
            match node.gap_fill_generation(store_id, root).await {
                Ok(()) => tracing::info!(
                    capsule = %key,
                    "backfill: cached the whole capsule after a resource read from another node"
                ),
                Err(e) => tracing::warn!(
                    capsule = %key,
                    error = %e,
                    "backfill: whole-capsule pull did not complete (will re-attempt on the next miss)"
                ),
            }
        });
    }
}
