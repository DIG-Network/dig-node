//! `CoinsetResolver` — seam 1's production [`AnchoredRootResolver`] implementation, relocated
//! unchanged from `lib.rs` (#1285 W1b-3). Walks the store's DataStore singleton lineage on
//! coinset.org to resolve the chain-anchored root; the SAME authority `dig.getAnchoredRoot`,
//! `dig-resolver`, and the CLI clone/pull pin already use. NEVER consults the serving node.

use std::sync::Arc;

use digstore_chain::coinset::Coinset;
use digstore_chain::singleton::{sync_datastore, verify_pinned_root};
use digstore_core::Bytes32;

use crate::shared::chain_view::{AnchoredRootResolver, AnchoredStoreState};

/// Coinset client used to resolve chain-anchored roots. `DIG_NODE_COINSET`
/// overrides the API base (tests / alternate endpoints); defaults to mainnet
/// (api.coinset.org).
pub(crate) fn resolution_coinset() -> Coinset {
    match std::env::var("DIG_NODE_COINSET") {
        Ok(url) if !url.is_empty() => Coinset::with_url(url),
        _ => Coinset::mainnet(),
    }
}

/// Production resolver: walks the store's DataStore singleton lineage on
/// coinset.org (`digstore_chain::singleton::sync_datastore`) to the unspent tip
/// and returns its metadata root — exactly the source `dig.getAnchoredRoot` and
/// `dig-resolver` already use, and the same authority the CLI clone/pull pin
/// resolves against (`current_root`). NEVER consults the serving node.
pub struct CoinsetResolver;

#[async_trait::async_trait]
impl AnchoredRootResolver for CoinsetResolver {
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        Ok(self.anchored_state(store_id).await?.map(|s| s.root))
    }

    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        match sync_datastore(&resolution_coinset(), launcher).await {
            Ok(store) => {
                // Convert chia_protocol::Bytes32 → digstore_core::Bytes32 (the
                // node's content-root type), mirroring the CLI clone/pull pin.
                let mut a = [0u8; 32];
                a.copy_from_slice(store.info.metadata.root_hash.as_ref());
                let mut o = [0u8; 32];
                o.copy_from_slice(store.info.owner_puzzle_hash.as_ref());
                Ok(Some(AnchoredStoreState {
                    root: Bytes32(a),
                    owner_puzzle_hash: Some(Bytes32(o)),
                }))
            }
            Err(e) => {
                // A "not minted yet" / "launcher unspent" lineage error is a
                // legitimate absence (no confirmed generation), distinct from an
                // unreachable chain. Either way the read FAILS CLOSED at the
                // caller; we only distinguish them for a clearer error message.
                let msg = e.to_string();
                if msg.contains("not minted") || msg.contains("unspent") {
                    Ok(None)
                } else {
                    Err(msg)
                }
            }
        }
    }

    /// Bounded, fail-closed pinned-root verification (#747): confirm `pinned_root` is the store's
    /// CURRENT on-chain generation via a single launcher-hint query — NEVER the full lineage walk
    /// that aborts on one unparseable intermediate spend. Defers entirely to
    /// [`digstore_chain::singleton::verify_pinned_root`] (the same authority the CLI clone/pull pin
    /// uses); an `Err` (mismatch / no confirmed generation / unreachable chain) means "do not serve".
    async fn verify_pinned_root(
        &self,
        store_id: &[u8; 32],
        pinned_root: Bytes32,
    ) -> Result<(), String> {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        let pinned = chia_protocol::Bytes32::new(pinned_root.0);
        verify_pinned_root(&resolution_coinset(), launcher, pinned)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The default anchored-root resolver (production coinset walk).
pub(crate) fn default_anchored_resolver() -> Arc<dyn AnchoredRootResolver> {
    Arc::new(CoinsetResolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes the `DIG_NODE_COINSET` env mutation across tests in this module (env vars are
    // process-global; a poisoned guard is still usable — we only need mutual exclusion).
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    /// Regression guard for the launcher-anchored read-root pin (#747 / #841 / #852-node,
    /// hardened by digstore #1473). `CoinsetResolver::verify_pinned_root` delegates to
    /// `digstore_chain::singleton::verify_pinned_root`, whose contract is fail-closed: it returns
    /// `Err` — NEVER a false `Ok` — whenever a pinned root cannot be positively chain-anchored
    /// (chain unreachable, no launcher-anchored unspent singleton, or root mismatch). This asserts
    /// the production call site propagates that `Err` (do-not-serve) rather than swallowing it, so
    /// the read-path pin (§4.2) cannot be tricked into serving an unanchored generation.
    ///
    /// The DEEP forge coverage — proving an impostor singleton that curries `launcher_id ==
    /// store_id` from a FOREIGN launcher is REJECTED while a genuine launcher-descended tip is
    /// ACCEPTED — lives in digstore's `golden_read_proof.rs` golden test at rev `4c34f0be`, because
    /// forging that scenario needs a `ChainReads` mock with crafted launcher/parent coin records
    /// that `CoinsetResolver` (which hardcodes the live HTTP `resolution_coinset()`) cannot inject
    /// without new chain-simulator scaffolding beyond this unit's scope. Here we lock the node-layer
    /// wiring: an unanchorable pin fails closed.
    // The `ENV_GUARD` is a plain std `Mutex` deliberately held across the `.await` to serialize the
    // process-global `DIG_NODE_COINSET` mutation for the whole verify call; contention is nil (this
    // is the only test that touches the var), so the async-mutex lint does not apply here.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn verify_pinned_root_fails_closed_when_the_chain_cannot_anchor_the_pin() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        // Point the resolver at a closed loopback port so the chain read cannot succeed — a
        // stand-in for "cannot positively anchor this pinned root".
        std::env::set_var("DIG_NODE_COINSET", "http://127.0.0.1:1");

        let store_id = [7u8; 32];
        let pinned = Bytes32([0x11; 32]);
        let outcome = CoinsetResolver.verify_pinned_root(&store_id, pinned).await;

        std::env::remove_var("DIG_NODE_COINSET");

        assert!(
            outcome.is_err(),
            "an unanchorable pinned root MUST fail closed (do not serve), never Ok: {outcome:?}"
        );
    }
}
