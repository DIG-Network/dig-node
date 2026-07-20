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
    /// last-used time. Walks `<cache>/modules/<storeId_hex>/<root_hex>.module`
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
    /// (deduped via `Node::backfilling`, so a burst of resource reads for the same not-yet-held store
    /// triggers ONE whole-`.dig` pull, not one per read). The pull reuses
    /// [`Self::gap_fill_generation`] — the authenticated §21 whole-store sync, chain-anchored-root
    /// pinned + DHT-announced — so a backfilled capsule is verified exactly like every other cached
    /// generation.
    fn maybe_backfill_capsule(&self, store_hex: &str, root_hex: &str);

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
        // Outer level: one directory per store id (hex). Inner: `<root>.module`.
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
                // A capsule module is `<root_hex>.module`; skip anything else.
                let Some(root_hex) = path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .and_then(|f| f.strip_suffix(".module"))
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
        fn is_hex64(s: &str) -> bool {
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
        }
        if !is_hex64(store_id_hex) {
            return Err(format!("invalid store_id (want 64-hex): {store_id_hex}"));
        }
        if !is_hex64(root_hex) {
            return Err(format!("invalid root (want 64-hex): {root_hex}"));
        }
        let path = crate::module_path(&self.cache_dir, store_id_hex, root_hex);

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
        // Already cached → report its size, no network.
        let existing = crate::module_path(&self.cache_dir, store_id_hex, root_hex);
        if let Ok(md) = std::fs::metadata(&existing) {
            return Ok((md.len(), root_hex.to_string()));
        }
        // Serialize on-demand writes so two fetches of the same capsule don't race.
        let _guard = self.cache_lock.lock().await;
        // sync_module_from returns true only when the served root == requested
        // root; either way the module lands under its SERVED root, so we read the
        // file back to report size + confirm the capsule is now present.
        let matched = self
            .sync_module_from(&self.upstream, store_id_hex, root_hex)
            .await;
        let path = crate::module_path(&self.cache_dir, store_id_hex, root_hex);
        match std::fs::metadata(&path) {
            Ok(md) => Ok((md.len(), root_hex.to_string())),
            Err(_) if matched => {
                // matched but no file: should not happen, surface it.
                Err("sync reported a match but the module is not cached".to_string())
            }
            Err(_) => Err(format!(
                "could not fetch capsule {store_id_hex}:{root_hex} (no §21 identity, \
                 not authorized, or served root differs)"
            )),
        }
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
        if !module_exists(&self.cache_dir, &store_hex, &root_hex) {
            return Err(format!(
                "gap-fill for {store_hex}:{root_hex} pulled a module but not at the confirmed root"
            ));
        }

        // Best-effort: refresh the DHT provider records so peers find this node as a holder of the
        // newly-synced capsule (§14.1). The peer-network bring-up installs the announce hook; when no
        // peer network is running (FFI path) this is a no-op.
        self.refresh_dht_inventory().await;
        Ok(())
    }

    fn maybe_backfill_capsule(&self, store_hex: &str, root_hex: &str) {
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
        // Dedup: claim the in-flight slot; if another read already claimed it, do nothing (a burst of
        // resource reads for the same not-yet-held store triggers ONE whole-capsule pull).
        {
            let mut inflight = self.backfilling.lock().unwrap_or_else(|p| p.into_inner());
            if !inflight.insert(key.clone()) {
                return; // a backfill for this capsule is already running
            }
        }
        let root = Bytes32(root_bytes);
        tokio::spawn(async move {
            match node.gap_fill_generation(store_id, root).await {
                Ok(()) => tracing::debug!(
                    capsule = %key,
                    "backfill: cached the whole capsule after a resource read from another node"
                ),
                Err(e) => tracing::debug!(
                    capsule = %key,
                    error = %e,
                    "backfill: whole-capsule pull did not complete (will re-attempt on the next miss)"
                ),
            }
            // Release the in-flight slot so a later miss can re-attempt if this one failed.
            node.backfilling
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
        });
    }

    fn set_self_ref(&self, weak: Weak<Node>) {
        let _ = self.self_ref.set(weak);
    }

    fn arc_self(&self) -> Option<Arc<Node>> {
        self.self_ref.get().and_then(Weak::upgrade)
    }
}
