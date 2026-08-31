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

use crate::{module_exists, CachedCapsule, Node};

/// Walk `<modules_root>/<store_id_hex>/<root_hex>.dig` and describe every capsule this node holds.
///
/// BLOCKING (`read_dir` plus one `stat` per entry) — drive it from a blocking thread, never from an
/// async worker: on a network-mounted cache each of those is a round trip. It reads only directory
/// metadata (name, size, mtime) and never opens a capsule's bytes, so its cost is exactly one `stat`
/// per held generation.
pub(crate) fn list_cached_capsules(modules_root: &std::path::Path) -> Vec<CachedCapsule> {
    let mut out = Vec::new();
    // Outer level: one directory per store id (hex). Inner: `<root>.dig` (or a legacy `<root>.module`).
    let Ok(stores) = std::fs::read_dir(modules_root) else {
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
            // Provenance is read HERE, from the durable `<root>.relay` sidecar beside the module, and
            // nowhere else: this scan is the only producer of `CachedCapsule` in production, so every
            // consumer of the inventory — every announce cause, whatever triggered it — sees the same
            // answer the artifact itself carries (dig-node#276).
            let provenance = match crate::capsule_key::relay_marker_beside(&path) {
                Some(marker) if marker.exists() => crate::CapsuleProvenance::Relayed,
                _ => crate::CapsuleProvenance::Held,
            };
            out.push(CachedCapsule {
                store_id: store_hex.clone(),
                root: root_hex,
                size_bytes: md.len(),
                last_used_unix_ms,
                provenance,
            });
        }
    }
    out
}

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
    /// `(store_id, root)` down from other nodes, merkle-verify it against `root`, land it in
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
    /// ## The `root` argument — normally chain-anchored, with ONE sanctioned exception
    /// `root` is NORMALLY the chain-anchored tip a caller already resolved (the chain watcher, the §21
    /// sync, the fetch-side backfill), so gap-fill targets a chain-confirmed generation. The ONE
    /// sanctioned exception is the INBOUND-DEMAND pull (§7.10d(b), [`Node::note_inbound_demand`]), which
    /// passes a PEER-supplied `(store, root)` deliberately — demand-caching's whole purpose is to warm
    /// the specifically-requested capsule, so it MUST NOT be re-routed through the anchored-root
    /// resolver. A caller-chosen root is safe here because the anchor binds at two DOWNSTREAM points
    /// regardless of who chose it: the pulled module is bound to `root` by merkle verification, and it
    /// is never SERVED as current unless `root` equals the chain-anchored tip (the serve-time read-path
    /// pin, §14.4). So the worst a caller-chosen root can do is cache REAL near-neighbourhood content of
    /// a possibly-OLD generation (#1623) — never fabricated, junk, or out-of-neighbourhood content. The
    /// inbound-demand path additionally confines the caller to this node's keyspace neighbourhood (the
    /// XOR-proximity admission, §7.10d) before it ever passes a peer-supplied root in.
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
        // Handed to a blocking thread rather than run inline: this is `std::fs` `read_dir` + `stat`
        // per held capsule, and on a node whose cache is a NETWORK mount (the S3-backed store, #1943)
        // every one of those is a round trip. Running them on an async worker parks a runtime thread
        // for the duration, stalling whatever else was scheduled onto it (dig_ecosystem#1974).
        let modules_root = self.cache_dir.join("modules");
        tokio::task::spawn_blocking(move || list_cached_capsules(&modules_root))
            .await
            .unwrap_or_default()
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
        // The marker's lifetime is the module's (dig-node#276): left behind, it would suppress the
        // announce of a later, genuinely-held re-acquisition of this same generation.
        crate::capsule_key::discard_relay_marker_beside(&canon);
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
                // CacheFetchAndCache RPC, and now the cache.pushCapsule seed-push #1476) shares the ONE
                // post-land tail below, so announcing there makes them all discoverable identically. We
                // only reach this point on a FRESH land (an already-cached capsule returned at the top
                // before any network), so the announce fires exactly once per newly-held capsule — no
                // double-announce. The `_guard` above already holds `cache_lock`.
                self.announce_and_bound_after_land(capsule.identity()).await;
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
    /// The ONE land+announce+bound site for a fully-materialized capsule (#1476).
    ///
    /// Writes `bytes` to the capsule's canonical `<cache>/modules/<store>/<root>.dig` path
    /// (content-addressed, atomic temp-write + rename via [`write_atomic`](crate::write_atomic)),
    /// then — ONLY on a FRESH land — runs the shared post-land tail
    /// ([`announce_and_bound_after_land`](Self::announce_and_bound_after_land)): announce this node a
    /// DHT holder (§14.1 / #1423 flywheel) and sweep the size cap. Both the pull-land
    /// ([`CapsuleStore::cache_fetch_and_cache`]) and the push-land (`cache.pushCapsule`, #1476) share
    /// this tail, so a seeded capsule is discoverable byte-for-byte identically to a pulled one.
    ///
    /// IDEMPOTENT (#1476 D4/f): a capsule already on disk is a no-op — it neither re-writes the bytes
    /// nor fires a SECOND `HoldingsAnnounce`. Re-pushing a held capsule therefore never double-announces.
    /// Returns `(size_bytes, fresh)`, where `fresh` is `false` for the already-held no-op.
    ///
    /// The caller MUST hold `cache_lock` so a concurrent pull-land of the same capsule cannot race the
    /// write (matching `cache_fetch_and_cache`, which lands under the same lock).
    ///
    /// # `claim` is required, and that is the point (dig-node#436)
    ///
    /// Provenance is not carried in a capsule's bytes — they are content-addressed and identical
    /// whether this node pulled them for itself or for a stranger — so it lives in a `<root>.relay`
    /// sidecar that the inventory scan reads. Its ABSENCE means `Held`, and `Held` is the bondable
    /// state a mirror coin is minted against. A land route that simply forgot to write the marker
    /// therefore failed OPEN, spending the operator's $DIG on a stranger's content.
    ///
    /// Naming the claim is a required ARGUMENT rather than a step a caller performs afterwards, so a
    /// future land route cannot inherit `Held` by omission: there is no signature to call incorrectly.
    /// The same reasoning that made [`crate::CapsuleProvenance`] an enum with no `Default`, extended
    /// to the filesystem that was quietly supplying one.
    pub(crate) async fn land_capsule_bytes(
        &self,
        key: &crate::CapsuleKey,
        bytes: &[u8],
        claim: crate::seams::dig_peer::HolderClaim,
    ) -> Result<(u64, bool), String> {
        let path = key.module_path(&self.cache_dir);
        if let Ok(md) = std::fs::metadata(&path) {
            // Already a holder — do not re-write, do not re-announce (no double-announce). The claim
            // already recorded beside it stands: a re-push cannot silently PROMOTE a relayed capsule
            // into a bondable one, which is the same fail-closed direction the rest of this path takes.
            //
            // DELIBERATE, and it has a cost worth naming: a genuinely LOCAL re-push of a capsule this
            // node previously relayed stays `Relayed` until the capsule is evicted, so the operator
            // forgoes a bond they were entitled to. That is the direction to err in — it costs a bond
            // that could have been had, never a bond staked on a stranger's content. Changing it is a
            // decision that gets a ticket, not a quiet relaxation of this early return.
            return Ok((md.len(), false));
        }
        // PROVENANCE FIRST, and it is not optional (dig-node#436). The `<root>.relay` sidecar decides
        // whether this node later announces the capsule and stakes the operator's $DIG on it, and it
        // is recorded BEFORE the bytes become visible — so there is no window in which a capsule is
        // discoverable while its provenance is still unwritten. A marker that cannot be written fails
        // the land outright rather than landing unmarked, because unmarked reads as `Held`, and `Held`
        // is the bondable state: a silent failure here spends money.
        // The store directory must exist before the marker can be written into it. `write_atomic`
        // creates it for the capsule, but the marker is deliberately written FIRST, so it has to
        // create it too — otherwise a first-ever capsule for a store fails its land on a missing
        // directory. (It failed exactly that way when this guard was introduced, which is the correct
        // direction: refusing to land beats landing unmarked, because unmarked is bondable.)
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create the capsule's store directory: {e}"))?;
        }
        crate::seams::dig_peer::persist_holder_claim(&path, claim)
            .map_err(|_| "could not record the capsule's provenance".to_string())?;
        crate::write_atomic(&path, bytes).map_err(|e| {
            // The land failed, so the marker must not outlive it and mis-describe a later capsule that
            // arrives at the same path by a different route.
            let _ = crate::seams::dig_peer::persist_holder_claim(
                &path,
                crate::seams::dig_peer::HolderClaim::Announce,
            );
            format!("could not write the capsule: {e}")
        })?;
        self.announce_and_bound_after_land(key.identity()).await;
        Ok((bytes.len() as u64, true))
    }

    /// The shared post-land tail every ON-DEMAND land path runs (#1476, extracted from
    /// `cache_fetch_and_cache`): announce this node a discoverable DHT holder (§14.1 / #1423 — a no-op
    /// on the FFI path with no refresher installed), then run the tier-aware size-cap sweep so
    /// whole-capsule storage stays bounded at the cache cap (#1934). The caller already holds
    /// `cache_lock`, so this calls the LOCKED eviction core directly (the `_if_needed` wrapper re-takes
    /// `cache_lock` and would deadlock).
    async fn announce_and_bound_after_land(&self, admitted: dig_sex::CapsuleIdentity) {
        // The sweep runs FIRST, and the ordering is the point. It used to run second, so a land that
        // sacrificed a capsule to make room announced the arrival and then deleted the victim in
        // silence — the node advertised content it had just removed until some unrelated inventory
        // change happened to reconcile it, which on a quiet node is never (#267).
        let evicted = self.evict_modules_locked();
        // One delta for the whole event: what arrived, and what it cost. `after_admission` always
        // announces the admitted capsule, so a land that evicts nothing still advertises exactly as
        // before — the retraction is additive to that, never a replacement for it.
        self.advertise_holdings_change(&dig_sex::holdings::after_admission(admitted, &evicted))
            .await;
    }

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
        // Only where a peer network / upstream exists to pull from. This is a CAPABILITY check, not a
        // policy one — there is nothing to decide about on a node with no way to fetch.
        if self.p2p_content().is_none() {
            return;
        }
        // Need an owned `Arc<Node>` to spawn the detached pull. Installed by the standalone
        // peer-network bring-up; `None` on the FFI path (which also has no p2p_content, so we already
        // returned above) or during teardown.
        let Some(node) = self.arc_self() else {
            return;
        };
        // Need a concrete, valid (store, root). A rootless/`"latest"` read names no capsule and is
        // skipped — the read path resolves the tip separately — and `CapsuleKey::parse` is the one
        // boundary at which untrusted key bytes become a usable capsule identity.
        let Some(capsule_key) = crate::capsule_key::CapsuleKey::parse(store_hex, root_hex) else {
            return;
        };
        let capsule = capsule_key.identity();

        // THE DECISION (SPEC §5, `dig_sex::acquisition`). The switch, the held check and the
        // in-flight check used to be three hand-rolled guards here; they are one crate call now, so
        // this node and every other consumer answer "should a remote read warm the whole capsule?"
        // the same way, and the reason is reported rather than collapsed into an early return.
        let decision = dig_sex::acquisition::decide(
            crate::download::backfill_policy(),
            &capsule,
            crate::module_exists(self.cache_dir_path(), store_hex, root_hex),
            &self.capsule_acquisition.in_flight_capsules(),
        );
        if decision != dig_sex::AcquisitionDecision::Acquire {
            tracing::debug!(
                store = %store_hex,
                root = %root_hex,
                ?decision,
                "capsule backfill not started"
            );
            return;
        }

        let (Some(store_id), Some(root_bytes)) =
            (crate::dht::hex64(store_hex), crate::dht::hex64(root_hex))
        else {
            return; // unreachable: `CapsuleKey::parse` already admitted two canonical 64-hex ids
        };
        let key = format!("{store_hex}:{root_hex}");
        // The single-flight CLAIM stays here and stays load-bearing (#1614). `decide` reads the
        // in-flight set, which is a snapshot; this claim is atomic, and it also enforces the
        // CONCURRENCY CAP across DISTINCT generations that `dig-sex` has no concept of. The crate
        // decides whether an acquisition is warranted; the registry decides whether this node has a
        // slot to run it in, and both answers are required.
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
