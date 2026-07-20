//! `CoinsetResolver` — seam 1's production [`AnchoredRootResolver`] implementation, relocated
//! unchanged from `lib.rs` (#1285 W1b-3). Walks the store's DataStore singleton lineage on
//! coinset.org to resolve the chain-anchored root; the SAME authority `dig.getAnchoredRoot`,
//! `dig-resolver`, and the CLI clone/pull pin already use. NEVER consults the serving node.

use std::sync::Arc;

use digstore_chain::coinset::Coinset;
use digstore_chain::singleton::sync_datastore;
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
}

/// The default anchored-root resolver (production coinset walk).
pub(crate) fn default_anchored_resolver() -> Arc<dyn AnchoredRootResolver> {
    Arc::new(CoinsetResolver)
}
