//! `CoinsetResolver` — seam 1's production [`AnchoredRootResolver`] implementation, relocated
//! unchanged from `lib.rs` (#1285 W1b-3). Walks the store's DataStore singleton lineage on
//! coinset.org to resolve the chain-anchored root; the SAME authority `dig.getAnchoredRoot`,
//! `dig-resolver`, and the CLI clone/pull pin already use. NEVER consults the serving node.

use std::sync::Arc;

use digstore_chain::coinset::Coinset;
use digstore_chain::singleton::{sync_datastore, sync_datastore_with_history, verify_pinned_root};
use digstore_core::Bytes32;

use super::corroborated_resolver::CorroboratedResolver;
use super::endpoints::{ChainEndpoint, DnsReach};
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
///
/// This speaks to the ONE endpoint [`resolution_coinset`] names. It is the voice, not the
/// verdict: [`CorroboratedResolver`] holds several of these and serves an answer only when
/// independent ones agree (dig-node#365).
pub struct CoinsetResolver;

#[async_trait::async_trait]
impl AnchoredRootResolver for CoinsetResolver {
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        EndpointResolver::new(resolution_coinset())
            .anchored_root(store_id)
            .await
    }

    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        EndpointResolver::new(resolution_coinset())
            .anchored_state(store_id)
            .await
    }

    async fn verify_pinned_root(
        &self,
        store_id: &[u8; 32],
        pinned_root: Bytes32,
    ) -> Result<(), String> {
        EndpointResolver::new(resolution_coinset())
            .verify_pinned_root(store_id, pinned_root)
            .await
    }

    async fn verify_lineage_root(&self, store_id: &[u8; 32], root: Bytes32) -> Result<(), String> {
        EndpointResolver::new(resolution_coinset())
            .verify_lineage_root(store_id, root)
            .await
    }
}

/// The same walk, against ONE named endpoint rather than the process-wide default.
///
/// Split out from [`CoinsetResolver`] so corroboration has something to hold: a rule that needs
/// several voices needs a resolver that can be pointed at a specific one, and reading the endpoint
/// from a process-global environment variable inside the walk makes every instance the same voice
/// no matter how many are constructed.
pub(crate) struct EndpointResolver {
    /// The coinset-protocol client for this endpoint.
    chain: Coinset,
}

impl EndpointResolver {
    /// A resolver that walks `chain` and nothing else.
    pub fn new(chain: Coinset) -> Self {
        Self { chain }
    }
}

#[async_trait::async_trait]
impl AnchoredRootResolver for EndpointResolver {
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        Ok(self.anchored_state(store_id).await?.map(|s| s.root))
    }

    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        match sync_datastore(&self.chain, launcher).await {
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
        verify_pinned_root(&self.chain, launcher, pinned)
            .await
            .map_err(|e| e.to_string())
    }

    /// Fail-closed lineage-membership check (#2088): walk the store's DataStore singleton lineage
    /// on coinset.org, collecting EVERY committed root (`sync_datastore_with_history`), and confirm
    /// `root` is one of them. This is the same authenticated walk the tip pin uses, extended to
    /// yield the full ordered capsule history so a generation-resolution redirect to an older
    /// `serve_root` is honoured ONLY when that root is a genuine on-chain generation of THIS store —
    /// never an attacker-fabricated root smuggled in via the tip's non-anchored §13 manifest. Any
    /// `Err` (root not in the lineage, store not minted, or the chain unreachable) means "do not
    /// redirect the serve to `root`".
    async fn verify_lineage_root(&self, store_id: &[u8; 32], root: Bytes32) -> Result<(), String> {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        match sync_datastore_with_history(&self.chain, launcher).await {
            Ok((_store, history)) => {
                if history
                    .history
                    .iter()
                    .any(|capsule| capsule.root_hash == root)
                {
                    Ok(())
                } else {
                    Err(format!(
                        "root {} is not in the store's on-chain lineage (chain is the authority)",
                        root.to_hex()
                    ))
                }
            }
            // Cannot positively place the root in the lineage (not minted / lineage broken /
            // chain unreachable) ⇒ fail closed: the redirect MUST NOT be honoured.
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The coinset-protocol endpoint the mainnet default speaks to.
///
/// Named here rather than left implicit inside `Coinset::mainnet()` because the independence rule
/// needs an authority to resolve, and a default endpoint with no URL cannot be compared against an
/// operator's second one.
const MAINNET_ENDPOINT: &str = "https://api.coinset.org";

/// Every chain endpoint the node may ask, in configuration order.
///
/// `DIG_NODE_CHAIN_ENDPOINTS` is a comma-separated list and is what turns single-source resolution
/// into corroborated resolution — an operator who names two independently-hosted coinset-protocol
/// endpoints gets the agreement rule; one who names none gets today's behaviour.
///
/// `DIG_NODE_COINSET` keeps its existing meaning (a single override, used by tests and by
/// operators pointing at one alternate endpoint) and is honoured when the list is unset, so no
/// existing configuration changes meaning. Unparseable entries are DROPPED rather than defaulted:
/// silently substituting the mainnet endpoint for a typo would let a misconfiguration masquerade
/// as a second voice.
pub(crate) fn resolution_endpoints() -> Vec<ChainEndpoint> {
    let configured = match std::env::var("DIG_NODE_CHAIN_ENDPOINTS") {
        Ok(list) if !list.trim().is_empty() => list,
        _ => std::env::var("DIG_NODE_COINSET")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| MAINNET_ENDPOINT.to_string()),
    };
    configured
        .split(',')
        .filter_map(ChainEndpoint::parse)
        .collect()
}

/// The default anchored-root resolver: the configured endpoints, believed only on agreement.
///
/// With one endpoint configured — the default install — this resolves exactly as
/// [`CoinsetResolver`] always did, from a single third party. That limitation is REAL and is
/// recorded in `SPEC.md` rather than dressed up: see [`CorroboratedResolver`] for why
/// refusing instead was rejected, and dig-node#365 for the blast radius it leaves.
pub(crate) fn default_anchored_resolver() -> Arc<dyn AnchoredRootResolver> {
    Arc::new(CorroboratedResolver::new(
        resolution_endpoints(),
        Arc::new(DnsReach),
        Arc::new(|endpoint: &ChainEndpoint| {
            Arc::new(EndpointResolver::new(Coinset::with_url(
                endpoint.url.clone(),
            ))) as Arc<dyn AnchoredRootResolver>
        }),
    ))
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
