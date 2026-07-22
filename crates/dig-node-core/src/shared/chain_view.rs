//! The injectable on-chain root resolver — the node's "view" of chain-anchored store state.
//!
//! Moved here unchanged from `lib.rs` (#1285 W1a): this is the trusted-root source for the
//! MANDATORY read-path pin (#127), consumed by both the local-content seam (a read serves against
//! the on-chain current root or fails closed, never trusting an upstream-/host-reported root) and
//! `chainwatch` (the same trait polls for gap-fill). Production uses `CoinsetResolver` (which stays
//! in `lib.rs` — a concrete coinset-walking implementation is seam-private, not shared
//! vocabulary); tests inject a deterministic mock.

use digstore_core::Bytes32;

/// Resolve a store's CHIP-0035 chain-anchored TIP root. This is the trusted-root
/// source for the MANDATORY read-path pin (#127): a content read serves against
/// the on-chain current root or fails closed — it never trusts an upstream-/
/// host-reported root.
///
/// Implemented as a trait so the read-path pin is unit-testable without a live
/// chain: production uses `CoinsetResolver` (walks the singleton lineage on
/// coinset.org); tests inject a deterministic resolver. `Ok(Some(root))` = the
/// resolved tip; `Ok(None)` = the store is not minted / has no confirmed
/// generation (treated as fail-closed by the caller); `Err` = the chain was
/// unreachable (also fail-closed).
#[async_trait::async_trait]
pub trait AnchoredRootResolver: Send + Sync {
    /// Resolve `store_id`'s current on-chain root, or `None` if the store has no
    /// confirmed generation yet, or `Err` if the chain is unreachable.
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String>;

    /// The richer form of [`anchored_root`](Self::anchored_root): the SAME resolution, ALSO
    /// carrying the store's current on-chain OWNER puzzle hash — the future tip recipient
    /// surfaced by the local content-serve path as `X-Dig-Owner-Puzzle-Hash` (#486). Default
    /// impl wraps `anchored_root` with `owner_puzzle_hash: None` (used by resolvers — e.g. test
    /// mocks — that only know the root). `CoinsetResolver` overrides this to capture BOTH
    /// fields from the single `sync_datastore` walk it already performs, so content-serve never
    /// needs a second coinset round trip to learn the owner.
    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        Ok(self
            .anchored_root(store_id)
            .await?
            .map(|root| AnchoredStoreState {
                root,
                owner_puzzle_hash: None,
            }))
    }

    /// Fail-closed, BOUNDED verification that `pinned_root` is the store's CURRENT on-chain
    /// generation — WITHOUT the full singleton-lineage walk [`anchored_root`](Self::anchored_root)
    /// performs. A rooted local content read (`dig://<store>:<root>`, the §5.3 loopback tier) MUST
    /// chain-anchor its pinned root before serving; the lineage walk parses every generation and
    /// ABORTS on a single unparseable intermediate spend (#747 "parse next store: missing child"),
    /// so a perfectly valid pinned root becomes unreadable.
    ///
    /// Production [`CoinsetResolver`](crate::CoinsetResolver) overrides this with
    /// `digstore_chain::singleton::verify_pinned_root` — one `unspent_coins_by_hint` query on the
    /// launcher id + a read of the ONE creating spend, no per-generation walk. The default impl
    /// falls back to the walk-based [`anchored_root`](Self::anchored_root) + equality, so
    /// deterministic test mocks (which only know the tip) keep working unchanged.
    ///
    /// Returns `Ok(())` only when `pinned_root` equals the live on-chain root. Any `Err` —
    /// mismatch (stale/never-anchored root), no confirmed generation, or an unreachable chain —
    /// means the caller MUST NOT serve (fail closed, §5.3 / NC-9 anti-rollback).
    async fn verify_pinned_root(
        &self,
        store_id: &[u8; 32],
        pinned_root: Bytes32,
    ) -> Result<(), String> {
        match self.anchored_root(store_id).await? {
            Some(tip) if tip == pinned_root => Ok(()),
            Some(tip) => Err(format!(
                "pinned root {} is not the store's current on-chain root {} (chain is the authority)",
                pinned_root.to_hex(),
                tip.to_hex()
            )),
            None => {
                Err("store has no confirmed on-chain generation (chain is the authority)".into())
            }
        }
    }
}

/// The store's on-chain DataStore singleton state, as resolved by walking its lineage to the
/// unspent tip (`sync_datastore`): its CURRENT content root (the read-path anchor, #127) and its
/// CURRENT owner puzzle hash (the tip recipient, #486). Bundled because both come from the SAME
/// chain read — no second coinset call is needed to serve owner metadata alongside the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredStoreState {
    pub root: Bytes32,
    /// `None` when the resolver cannot supply it (see [`AnchoredRootResolver::anchored_state`]'s
    /// default impl) — content-serve OMITS `X-Dig-Owner-Puzzle-Hash` rather than guess.
    pub owner_puzzle_hash: Option<Bytes32>,
}
