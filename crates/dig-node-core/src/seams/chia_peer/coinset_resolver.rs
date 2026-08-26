//! `CoinsetResolver` — seam 1's production [`AnchoredRootResolver`] implementation, relocated
//! unchanged from `lib.rs` (#1285 W1b-3). Walks the store's DataStore singleton lineage on
//! coinset.org to resolve the chain-anchored root; the SAME authority `dig.getAnchoredRoot`,
//! `dig-resolver`, and the CLI clone/pull pin already use. NEVER consults the serving node.

use std::sync::Arc;

use digstore_chain::coinset::{ChainReads, Coinset};
use digstore_chain::singleton::{sync_datastore, sync_datastore_with_history, verify_pinned_root};
use digstore_core::Bytes32;

use super::corroborated_resolver::{ChainVoice, CorroboratedResolver, Verdict};
use super::endpoints::{CachedReach, ChainEndpoint, DnsReach};
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
        AnchoredRootResolver::anchored_root(&EndpointResolver::new(resolution_coinset()), store_id)
            .await
    }

    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        AnchoredRootResolver::anchored_state(&EndpointResolver::new(resolution_coinset()), store_id)
            .await
    }

    async fn verify_pinned_root(
        &self,
        store_id: &[u8; 32],
        pinned_root: Bytes32,
    ) -> Result<(), String> {
        AnchoredRootResolver::verify_pinned_root(
            &EndpointResolver::new(resolution_coinset()),
            store_id,
            pinned_root,
        )
        .await
    }

    async fn verify_lineage_root(&self, store_id: &[u8; 32], root: Bytes32) -> Result<(), String> {
        AnchoredRootResolver::verify_lineage_root(
            &EndpointResolver::new(resolution_coinset()),
            store_id,
            root,
        )
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
    ///
    /// Held behind `dyn ChainReads` rather than as a concrete [`Coinset`] so the classification
    /// below can be exercised against a chain that answers one read and then stops. That sequence
    /// is the entire difference between the two possible orderings of the probe, and no live
    /// endpoint can be asked to produce it on demand.
    chain: Arc<dyn ChainReads>,
}

impl EndpointResolver {
    /// A resolver that walks `chain` and nothing else.
    pub fn new(chain: Coinset) -> Self {
        Self::over(Arc::new(chain))
    }

    /// The same resolver over any chain reader.
    pub fn over(chain: Arc<dyn ChainReads>) -> Self {
        Self { chain }
    }

    /// Could this endpoint be reached AT ALL, right now?
    ///
    /// `unspent_coins_by_hint` is the read `digstore_chain::singleton::verify_pinned_root` itself
    /// starts with, so an endpoint that answers this is one the verification below will be talking
    /// to. Answering is the whole signal: the coins are not inspected, only the fact that a
    /// response came back.
    async fn reached(&self, store_id: &[u8; 32]) -> Result<(), String> {
        self.chain
            .unspent_coins_by_hint(chia_protocol::Bytes32::new(*store_id))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// One endpoint speaking for itself, able to say NO as distinct from saying nothing.
///
/// # Where the classification comes from, and which way it errs
///
/// * `verify_lineage_root` needs no extra call: the walk ALREADY separates the two cases
///   structurally — a completed walk whose history lacks the root is a rejection, and a failed
///   walk is an unreachable chain.
/// * `verify_pinned_root` delegates to a digstore function that performs its own read and collapses
///   both outcomes into one error, so reachability has to be established by a separate probe.
///
/// # The probe runs BEFORE the verification, and the order is the property
///
/// Reachability is a fact that, once established, cannot be withdrawn: an endpoint that answered a
/// read HAS been reached, and a later failure says something about the endpoint's future, never
/// about its past. Probing first encodes that. Probing afterwards does not — it re-tests a fact
/// already settled, and a rejection whose follow-up probe happens to fail is then filed as
/// `Unreachable`, DROPPED by the agreement rule, and casts no veto.
///
/// That is not a theoretical ordering preference. `Unreachable` is the one verdict an attacker
/// gains by producing, because [`CorroboratedResolver`] discards it while a `Rejected` refuses the
/// whole resolution — so a probe placed after the verification is a mechanism for converting the
/// dissent of a source one can degrade into silence, and two lagging endpoints then carry the
/// serve. With the probe first, degrading a source's reachability can only cost its voice, never
/// convert it.
///
/// The residual misclassification runs the other way and is deliberate: a chain that drops BETWEEN
/// the probe and the verification records a genuine unreachability as a REJECTION, which refuses.
/// So the classification is wrong only in the direction that refuses, and the ordering above is
/// what makes that a property of the code rather than a claim made about it.
///
/// The cost is one extra `unspent_coins_by_hint` on the confirming path, beside the several reads
/// the verification already performs (hint, parent record, parent spend, and the launcher descent).
#[async_trait::async_trait]
impl ChainVoice for EndpointResolver {
    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        AnchoredRootResolver::anchored_state(self, store_id).await
    }

    async fn verify_pinned_root(&self, store_id: &[u8; 32], pinned_root: Bytes32) -> Verdict {
        // Establish "this source was reached" FIRST. Everything after this point is this
        // endpoint's OPINION, and an opinion is not un-formed by the chain going away afterwards.
        if let Err(why) = self.reached(store_id).await {
            return Verdict::Unreachable(why);
        }
        match AnchoredRootResolver::verify_pinned_root(self, store_id, pinned_root).await {
            Ok(()) => Verdict::Confirmed,
            Err(why) => Verdict::Rejected(why),
        }
    }

    async fn verify_lineage_root(&self, store_id: &[u8; 32], root: Bytes32) -> Verdict {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        match sync_datastore_with_history(self.chain.as_ref(), launcher).await {
            // The walk COMPLETED, so this endpoint has a real opinion about the lineage.
            Ok((_store, history)) => {
                if history.history.iter().any(|c| c.root_hash == root) {
                    Verdict::Confirmed
                } else {
                    Verdict::Rejected(format!(
                        "root {} is not in the store's on-chain lineage (chain is the authority)",
                        root.to_hex()
                    ))
                }
            }
            Err(e) => Verdict::Unreachable(e.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl AnchoredRootResolver for EndpointResolver {
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        Ok(AnchoredRootResolver::anchored_state(self, store_id)
            .await?
            .map(|s| s.root))
    }

    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        match sync_datastore(self.chain.as_ref(), launcher).await {
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
        verify_pinned_root(self.chain.as_ref(), launcher, pinned)
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
        match sync_datastore_with_history(self.chain.as_ref(), launcher).await {
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
        // Cached, because independence is recomputed on every content read and an uncached reach
        // makes that a `getaddrinfo` per read — twice on a read that falls back from the tip to
        // the bounded pinned-root check.
        Arc::new(CachedReach::new(DnsReach)),
        Arc::new(|endpoint: &ChainEndpoint| {
            Arc::new(EndpointResolver::new(Coinset::with_url(
                endpoint.url.clone(),
            ))) as Arc<dyn ChainVoice>
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

    // -- The probe ordering ------------------------------------------------------------------

    use chia_protocol::{Bytes32 as ChiaBytes32, Coin, CoinSpend, SpendBundle};
    use digstore_chain::coinset::{CoinInfo, CoinRecord};
    use digstore_chain::error::{ChainError, Result as ChainResult};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::endpoints::{Authority, EndpointReach};

    /// A chain that answers a BOUNDED number of hint reads and then stops answering.
    ///
    /// This is the one fixture shape that can tell the two probe orderings apart, and it took a
    /// deliberate design to build: a chain that fails EVERY read is `Unreachable` under both
    /// orderings, and a chain that answers every read is `Rejected` under both. Only a chain that
    /// is reachable for the FIRST read and gone by the second distinguishes "reachability
    /// established before the verification" from "reachability re-tested after it".
    ///
    /// `Ok(vec![])` is a real answer, not a shrug: `digstore_chain::singleton::verify_pinned_root`
    /// finds no candidate tip in it and returns its "no current unspent singleton" error — a
    /// determination made by a source that ANSWERED.
    struct DegradingChain {
        /// How many hint reads still succeed.
        answers_left: AtomicUsize,
    }

    impl DegradingChain {
        /// A chain that answers `answers` hint reads and fails every one after them.
        fn answering(answers: usize) -> Arc<Self> {
            Arc::new(Self {
                answers_left: AtomicUsize::new(answers),
            })
        }
    }

    #[async_trait::async_trait]
    impl ChainReads for DegradingChain {
        async fn unspent_coins_by_hint(&self, _hint: ChiaBytes32) -> ChainResult<Vec<Coin>> {
            match self
                .answers_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                }) {
                Ok(_) => Ok(Vec::new()),
                Err(_) => Err(ChainError::Chain("coinset unreachable".into())),
            }
        }
        async fn unspent_coins(&self, _ph: ChiaBytes32) -> ChainResult<Vec<Coin>> {
            unimplemented!("the pinned-root check reads by hint")
        }
        async fn coin_records_by_puzzle_hash(
            &self,
            _ph: ChiaBytes32,
            _include_spent: bool,
        ) -> ChainResult<Vec<CoinRecord>> {
            unimplemented!("the pinned-root check reads by hint")
        }
        async fn coin_record(&self, _name: ChiaBytes32) -> ChainResult<Option<CoinInfo>> {
            unimplemented!("no candidate tip is ever reached in this fixture")
        }
        async fn coin_spend(
            &self,
            _coin_id: ChiaBytes32,
            _spent_height: u32,
        ) -> ChainResult<Option<CoinSpend>> {
            unimplemented!("no candidate tip is ever reached in this fixture")
        }
        async fn peak_height(&self) -> ChainResult<u32> {
            unimplemented!("the pinned-root check does not read the peak")
        }
        async fn push(&self, _bundle: SpendBundle) -> ChainResult<()> {
            unimplemented!("resolution is read-only")
        }
        async fn estimate_fee(&self, _bundle: &SpendBundle, _target: u64) -> ChainResult<u64> {
            unimplemented!("resolution is read-only")
        }
    }

    /// A voice that confirms whatever it is asked — the honest majority a veto must survive.
    struct AlwaysConfirms;

    #[async_trait::async_trait]
    impl ChainVoice for AlwaysConfirms {
        async fn anchored_state(
            &self,
            _store_id: &[u8; 32],
        ) -> Result<Option<AnchoredStoreState>, String> {
            Ok(Some(AnchoredStoreState {
                root: Bytes32([0xAA; 32]),
                owner_puzzle_hash: None,
            }))
        }
        async fn verify_pinned_root(&self, _store_id: &[u8; 32], _pinned: Bytes32) -> Verdict {
            Verdict::Confirmed
        }
        async fn verify_lineage_root(&self, _store_id: &[u8; 32], _root: Bytes32) -> Verdict {
            Verdict::Confirmed
        }
    }

    /// One address per authority, in configuration order, so every endpoint is its own voice.
    struct DistinctReach;

    #[async_trait::async_trait]
    impl EndpointReach for DistinctReach {
        async fn addrs(
            &self,
            authority: &Authority,
        ) -> Result<std::collections::BTreeSet<std::net::IpAddr>, String> {
            let last = u8::try_from(authority.host.len() % 251).map_err(|e| e.to_string())?;
            Ok(std::collections::BTreeSet::from([std::net::IpAddr::from(
                [203, 0, 113, last],
            )]))
        }
    }

    /// A source that ANSWERED and then rejected still vetoes, even if its chain has since gone.
    ///
    /// # Why this is the composition and not a unit of the classifier
    ///
    /// `Unreachable` is the verdict [`CorroboratedResolver`] DISCARDS; `Rejected` is the one that
    /// refuses. So an ordering that re-tests reachability after a verification is not merely
    /// untidy — it is a way to turn the dissent of a source one can degrade into silence, and two
    /// lagging endpoints then carry the serve unopposed. Asserting the classifier's verdict alone
    /// would pin the shape without pinning the consequence, so the assertion below is made through
    /// the agreement rule, with two honest voices present to be outvoted by.
    #[tokio::test]
    async fn a_source_that_answered_then_rejected_still_vetoes_when_its_chain_drops() {
        let root = Bytes32([0xAA; 32]);
        let store = [7u8; 32];
        // One answer: the probe consumes it, and the verification's own hint read then fails. Under
        // the reverse ordering the verification consumes it (determining a rejection) and the probe
        // fails — which is exactly the state that used to be filed as silence.
        let degrading = DegradingChain::answering(1);

        let endpoints: Vec<ChainEndpoint> = ["https://a.example.org", "https://bb.example.org"]
            .iter()
            .map(|url| ChainEndpoint::parse(url).expect("a parseable fixture url"))
            .collect();
        let dissenter = ChainEndpoint::parse("https://ccc.example.org").expect("parses");
        let all = [endpoints.clone(), vec![dissenter.clone()]].concat();

        let honest_only = CorroboratedResolver::new(
            endpoints,
            Arc::new(DistinctReach),
            Arc::new(|_| Arc::new(AlwaysConfirms) as Arc<dyn ChainVoice>),
        );
        assert_eq!(
            honest_only.verify_pinned_root(&store, root).await,
            Ok(()),
            "the control: two honest voices confirm the pin. Without it every assertion below is \
             satisfied by a resolver that refuses unconditionally"
        );

        let dissent_url = dissenter.url.clone();
        let with_dissenter = CorroboratedResolver::new(
            all,
            Arc::new(DistinctReach),
            Arc::new(move |endpoint: &ChainEndpoint| {
                if endpoint.url == dissent_url {
                    Arc::new(EndpointResolver::over(degrading.clone())) as Arc<dyn ChainVoice>
                } else {
                    Arc::new(AlwaysConfirms) as Arc<dyn ChainVoice>
                }
            }),
        );
        let refusal = with_dissenter
            .verify_pinned_root(&store, root)
            .await
            .expect_err("a source that answered and then rejected must refuse the resolution");
        assert!(
            refusal.contains("REJECTED"),
            "the refusal must be the DISSENT rule. Classifying that source as UNREACHABLE drops \
             it, leaves two confirmations standing, and SERVES — which is the whole defect: \
             {refusal}"
        );
    }

    /// A chain that never answers at all is genuinely silent, and is dropped rather than vetoing.
    ///
    /// The control for the ordering above: without it, an implementation that returned
    /// [`Verdict::Rejected`] for every failure would satisfy the veto assertion while converting
    /// every endpoint outage into a total refusal to serve.
    #[tokio::test]
    async fn a_chain_that_never_answers_is_silence_not_dissent() {
        let voice = EndpointResolver::over(DegradingChain::answering(0));
        let verdict = ChainVoice::verify_pinned_root(&voice, &[7u8; 32], Bytes32([0xAA; 32])).await;
        assert!(
            matches!(verdict, Verdict::Unreachable(_)),
            "an endpoint that could not be reached AT ALL has said nothing, and a rule that read \
             it as dissent would take the node down on any single outage: {verdict:?}"
        );
    }
}
