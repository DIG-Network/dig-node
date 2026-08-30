//! The node's CHAIN TRANSPORT: the reads dig-app needs to build a spend, and the push that puts an
//! already-signed one on the network (dig_ecosystem#2376).
//!
//! # Why this is separate from `enable_live_broadcast`
//!
//! `DIG_WALLET_ENABLE_LIVE_BROADCAST` (§18.12) answers one question: *may the node's OWN custodied
//! wallet sign and send?* That is a custody decision and it stays default-OFF. It is NOT the same
//! question as *may the node look at the chain, and may it relay a bundle somebody ELSE already
//! signed* — and the two were previously answered by the same flag, which is why a default install
//! answered `WALLET_NO_CHAIN_SOURCE` to every wallet read and could not push at all. The reads
//! disclose nothing the node holds, so they are served on every install.
//!
//! The push is served on every install too, but NOT unconditionally: the node's own custodied
//! wallet will sign on request, so "somebody else signed it" has to be CHECKED rather than assumed.
//! With the flag off, [`super::rpc::WalletBackend::push_signed_bundle`] refuses any bundle spending
//! a coin at a puzzle hash the node custodies a key for. Without that check the flag would be
//! decorative — sign through the node, then hand the bundle back for relay, and the node's own
//! money is on mainnet with live broadcast disabled.
//!
//! # The client is built LAZILY
//!
//! Constructing the client dials the network. A node whose operator never opens a wallet surface
//! should make no such call, so the client is built on FIRST USE and shared thereafter. A build
//! failure is not cached as a permanent verdict: a node that was offline at 9am must be able to
//! answer at 10am.
//!
//! # Unknown is never zero
//!
//! Every read here returns `Err` when it could not reach a chain. It never degrades an unreachable
//! chain into an empty list or a zero: an empty answer would tell somebody who holds funds that
//! they hold nothing, and a spend built on that refuses with a shortfall that is not true.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chia_protocol::SpendBundle;
// Through `chia-query`'s own re-export rather than a second declaration of
// `dig-chainsource-interface`: the provider descriptor must be the SAME type `chia-query` compiled
// against, and a separately declared version could resolve to a different line of the crate and
// fail to unify (§2.4b's split-family trap).
use chia_query::provider_registry::interface::{ProviderId, ProviderInfo, ProviderKind};

use super::fallback::{
    ChainFallback, ChainPeerTier, CoinsetFallback, FallbackCoin, FallbackCoinSpend,
};
use super::spend::to_query_bundle;
use super::{Error, Result};

/// How long the pool's held-peer count stays believable without a fresh sign of life.
///
/// Three minutes, which is about 9.6 mainnet block intervals at the ~18.75 s target. A live Chia
/// peer announces `NewPeakWallet` roughly once a block, so the chance of every held peer being
/// honestly silent for this long is on the order of 0.007%. Past it, silence is far better
/// explained by sessions that are not delivering than by a chain that has stopped.
///
/// It is DERIVED from the protocol's own interval rather than chosen, and it is deliberately
/// generous: the cost of being too long is a stale number for a few minutes, while the cost of
/// being too short is a healthy node reporting its peers as unknown during ordinary block jitter.
pub(crate) const PEER_LIVENESS_WINDOW: Duration = Duration::from_secs(180);

/// What the transport has last SEEN of its own peer tier, so a held-peer count can be reported as
/// a measurement rather than as a belief nothing has challenged (#351).
///
/// # Why a held-peer count needs corroborating at all
///
/// `chia_query`'s count is the pool's held-entry registry, and an entry leaves it in exactly one
/// way: a request routed to that peer FAILS. But `Router::get_blockchain_state` consults the
/// coinset HTTP tier FIRST and falls back to the peers, so a node whose reads are all answered by
/// coinset never routes a request to a peer, never ejects one, and never has its belief
/// contradicted. On the #3159 fleet — every Chia peer and all outbound `tcp/8444` blocked, HTTPS
/// untouched — the count sat at 5 for 180 s while the node could reach zero.
///
/// The belief is not fabricated and it is not useless; it simply has **unbounded age** precisely
/// when the node is not using its peers, which is when an operator most wants to know.
///
/// # What counts as a sign of life
///
/// Two observations, both passive, neither of which dials anything:
///
/// * **the peers' peak advancing** — `NewPeakWallet` is a per-peer heartbeat, and the pool's peak
///   is fed only by held sessions, so a rise means at least one session delivered something; and
/// * **the held count changing** — which happens only on a real admission or a real ejection.
///
/// Neither is a peer's claim about ITSELF (NC-12): a peer asserting it is alive proves nothing,
/// whereas a peak this node's own pool recorded is a fact about the node's sockets.
///
/// # Which way it is allowed to be wrong
///
/// A frozen peak is ambiguous between "the sessions are dead" and "the chain is quiet", and this
/// cannot tell them apart. So it answers **unknown**, never zero and never the stale number — an
/// operator who cannot be told how many peers are held is much better served by being told that
/// than by a confident five.
#[derive(Debug, Default)]
pub(crate) struct PeerLiveness {
    /// When the tier was last observed to be alive, or `None` before the first observation and
    /// after the client goes away.
    confirmed_at: Option<Instant>,
    /// The peak carried by the previous observation, so a rise can be recognised.
    last_peak: Option<u32>,
    /// The held count carried by the previous observation, so a change can be recognised.
    last_count: Option<u32>,
}

impl PeerLiveness {
    /// Fold one raw tier reading into the liveness record and return the tier to REPORT.
    ///
    /// `now` is passed rather than read so a test can pin fixture time; a liveness window driven by
    /// the wall clock is untestable without sleeping for three minutes.
    ///
    /// An unobservable reading — no client exists — RESETS the record rather than ageing it. The
    /// next client is a different set of sockets, and carrying a previous client's confirmation
    /// across the gap would let a freshly built pool inherit an expiry it never earned.
    pub(crate) fn observe(&mut self, now: Instant, raw: ChainPeerTier) -> ChainPeerTier {
        let Some(count) = raw.peer_count else {
            *self = Self::default();
            return raw;
        };

        // A first sighting is itself an observation: the client exists and reports what it holds,
        // which is a fact established at this instant rather than one inherited from earlier.
        let alive = self.confirmed_at.is_none()
            || raw.peak_height != self.last_peak
            || Some(count) != self.last_count;
        if alive {
            self.confirmed_at = Some(now);
        }
        self.last_peak = raw.peak_height;
        self.last_count = Some(count);

        let fresh = self
            .confirmed_at
            .is_some_and(|seen| now.duration_since(seen) <= PEER_LIVENESS_WINDOW);

        ChainPeerTier {
            peer_count: fresh.then_some(count),
            // The peak is reported exactly as the peers gave it. It was already honest on the
            // fleet — it froze when they died — and it is documented as "what the peers announced"
            // rather than as a claim about now.
            peak_height: raw.peak_height,
        }
    }
}

/// The outcome of pushing an already-signed bundle to the network.
///
/// `accepted: false` is a mempool that LOOKED at the bundle and refused it — a fact about the
/// bundle. Failing to reach a mempool at all is an `Err` from [`ChainTransport::push`] instead,
/// because the two demand opposite remedies: build a different bundle, versus retry this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// Whether the mempool admitted the bundle.
    pub accepted: bool,
    /// The bundle's transaction id (its name), lowercase 64-hex. Reported only on acceptance —
    /// a refused bundle has no transaction to point at.
    pub transaction_id: Option<String>,
    /// The mempool's own words for the refusal, when it refused.
    pub rejection: Option<String>,
}

/// Pushes an ALREADY-SIGNED bundle to the network.
///
/// A trait rather than a concrete client so the control surface can be driven end to end without a
/// mainnet push: the shipped implementation is [`ChainTransport`], and a test double stands in for
/// the network. It takes a complete bundle and nothing else — there is no key, seed or unsigned
/// plan in this signature, and there may never be (§908).
#[async_trait]
pub trait SignedBundlePusher: Send + Sync {
    /// Relay `bundle`. A mempool refusal is `Ok` with `accepted: false`; failing to REACH a mempool
    /// is `Err`.
    async fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome>;
}

/// The stable identifier this node's chain source registers itself under.
///
/// Named once rather than written at the construction site: an identifier a registry orders and
/// de-duplicates on is a contract with whatever reads it, and two spellings of it are two
/// providers.
pub const CHAIN_SOURCE_PROVIDER_ID: &str = "dig-node/chia-query";

/// A shared, lazily-built `chia_query` client serving the wallet's chain reads and its push.
///
/// Also the wallet's [`ChainFallback`] tier, so a balance, a coin read and a push all speak to ONE
/// client rather than three — and so the tier a read reports (`"fallback"`) stays truthful.
pub struct ChainTransport {
    /// The node's chain sources — the sole owner of the peer fabric and the registry that names
    /// it ([`super::sources`]). The transport reads THROUGH it rather than building its own, which
    /// is what makes NC-12's "no path constructs its own peer fabric outside the registry" a
    /// property of the code instead of a statement about a registry that did not exist.
    sources: Arc<super::sources::NodeChainSources>,
    /// ARBITRARY coin reads, served by this node's own peers and believed only on agreement
    /// (dig_ecosystem#3032).
    ///
    /// `None` only where no wallet database exists to cache into — a bare transport built by a
    /// test. Where it is attached it REPLACES the third-party oracle for the two reads a lineage
    /// walk composes, rather than sitting in front of it: falling back to the oracle after a
    /// refused quorum would let one endpoint overrule the peers whenever they failed to agree,
    /// which is the trusted-peer dependency this exists to remove.
    peer_reads: Option<Arc<super::peer_reads::PeerCorroboratedReads>>,
    /// What this transport has last seen of its own peer tier, so the held-peer count is reported
    /// as a measurement rather than as a belief nothing has challenged (#351). See [`PeerLiveness`].
    peer_liveness: StdMutex<PeerLiveness>,
}

impl Default for ChainTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainTransport {
    /// A transport that has not yet dialed anything.
    pub fn new() -> Self {
        Self {
            sources: Arc::new(super::sources::NodeChainSources::new()),
            peer_reads: None,
            peer_liveness: StdMutex::default(),
        }
    }

    /// Serve arbitrary coin reads from this node's OWN peers, corroborated and cached in `db`.
    ///
    /// Without this the two arbitrary reads fall through to the third-party oracle, which a node
    /// with no upstream configured cannot reach at all — the state that made a fully-synced node
    /// with five peers report that it could not read its owner's profile.
    #[must_use]
    pub fn with_peer_reads(mut self, db: super::db::WalletDb) -> Self {
        self.peer_reads = Some(Arc::new(super::peer_reads::PeerCorroboratedReads::new(
            Arc::new(super::peer_reads::DialedPeerSample::mainnet()),
            db,
        )));
        self
    }

    /// The shared client, building it on first use.
    ///
    /// A failure to build is an `Err` and is NOT cached — the next call tries again, so a node that
    /// starts offline becomes useful the moment its network does.
    async fn client(&self) -> Result<Arc<chia_query::ChiaQuery>> {
        self.sources.client().await
    }

    /// The one shared client, for a consumer that needs the client ITSELF rather than a read.
    ///
    /// This exists so the live-broadcast wiring (§18.12) can be built on the SAME pool that serves
    /// the wallet's reads. It used to build its own, which gave a live node two independent sets of
    /// full-node sessions with two notions of the peak (dig_ecosystem#2761).
    ///
    /// It is the lazy build, not a second one: the first caller to need a client — a read or the
    /// live wiring — is the one that dials, and every later caller gets that same client.
    pub(crate) async fn shared_client(&self) -> Result<Arc<chia_query::ChiaQuery>> {
        self.client().await
    }

    /// A [`Broadcaster`](super::spend::Broadcaster) that pushes through the ONE shared client.
    ///
    /// The narrow counterpart to [`Self::chain_source`], and it exists for the same reason: a
    /// consumer that needs to SEND a signed bundle needs the ability to push, not the client
    /// itself. Handing out [`Self::shared_client`] would hand out every other power the client has,
    /// and building a second client is what gave a live node two independent sets of full-node
    /// sessions with two notions of the peak (dig_ecosystem#2761).
    ///
    /// It is deliberately NOT an `impl Broadcaster for ChainTransport`. An unused one sat in this
    /// file once and made a one-line `.with_broadcaster(chain.clone())` compile, pass every test,
    /// and silently enable node-custodied sending on a default install. A caller must ask for a
    /// broadcaster by name, and asking is a visible line in a diff.
    ///
    /// # Errors
    ///
    /// The lazy client build — this node could not reach a chain at all. Not cached, so a later
    /// call tries again; a node that starts offline can broadcast the moment its network returns.
    pub async fn broadcaster(&self) -> Result<Arc<dyn super::spend::Broadcaster>> {
        let client = self.shared_client().await?;
        Ok(Arc::new(super::spend::ChiaQueryBroadcaster::new(client)))
    }

    /// This transport's chain reads presented as the canonical
    /// [`ChainSource`](chia_query::provider_registry::interface::ChainSource) — the trait every DIG consumer of
    /// chain state depends on.
    ///
    /// It is a VIEW of the one shared client, never a second one. `chia-query` already implements
    /// the trait ([`ChiaQueryProvider`]), so nothing here re-derives a chain read; building a
    /// separate source for a new consumer is what gave a live node two independent peer pools with
    /// two notions of the peak (dig_ecosystem#2761), and this method exists so the next consumer
    /// cannot repeat it.
    ///
    /// `handle` MUST belong to a **multi-thread** tokio runtime: the returned provider is
    /// synchronous and bridges each read with `run_blocking`, which fails closed with a clear
    /// error on a current-thread runtime rather than deadlocking. An async caller must additionally
    /// wrap each read in [`tokio::task::spawn_blocking`] so a blocking read never occupies an async
    /// worker.
    ///
    /// # Errors
    ///
    /// The lazy client build — i.e. this node could not reach a chain at all. Not cached, so a
    /// later call tries again.
    pub async fn chain_source(
        &self,
        handle: tokio::runtime::Handle,
    ) -> Result<chia_query::provider_registry::ChiaQueryProvider> {
        let client = self.shared_client().await?;
        Ok(chia_query::provider_registry::ChiaQueryProvider::new(
            client,
            handle,
            ProviderInfo {
                id: ProviderId(std::borrow::Cow::Borrowed(CHAIN_SOURCE_PROVIDER_ID)),
                // `Custom` rather than `LocalNode`, because the router behind it is not this
                // node's peers: with `coinset_fallback_enabled` — the default every production
                // fabric is built from — it asks `api.coinset.org` FIRST and consults the peers
                // this node dialled only when that read fails. It is not a race, and the peers do
                // not corroborate the answer.
                //
                // So this provider's ANSWERS are the oracle's whenever the oracle is reachable,
                // and a peer-tracked value with no agreement step when it is not. It belongs to
                // the oracle's independence group for exactly that reason
                // (`super::sources::independence_group_for`, which derives the group from what a
                // fabric can REACH after registering one as its own group made a 2-of-2
                // independent-group custody quorum satisfiable by a single HTTPS endpoint —
                // measured on a client holding no peers at all).
                //
                // Nothing registers this provider in a `ProviderRegistry` today. Anything that
                // does MUST take its group from `ChiaQueryProvider::independence_group()` rather
                // than from this `kind`, or it repeats that incident.
                kind: ProviderKind::Custom,
                priority: 0,
                // Answers are believed because the tier that produced them was believed, not
                // because they carry a proof this node checked.
                trustless: false,
            },
        ))
    }

    /// A transport that already HAS its client, so nothing in the test dials.
    ///
    /// Seeding the client is what makes pointer identity assertable: a consumer that quietly built
    /// its own pool returns a different `Arc`, which no agreement-based assertion could distinguish
    /// from sharing.
    #[cfg(test)]
    pub(crate) fn with_client(client: Arc<chia_query::ChiaQuery>) -> Self {
        Self {
            sources: Arc::new(super::sources::NodeChainSources::with_client(client)),
            peer_reads: None,
            peer_liveness: StdMutex::default(),
        }
    }

    /// Serve the corroborated reads from `reads`, so a test can script the peers a round hears.
    #[cfg(test)]
    pub(crate) fn with_peer_reads_arc(
        mut self,
        reads: Arc<super::peer_reads::PeerCorroboratedReads>,
    ) -> Self {
        self.peer_reads = Some(reads);
        self
    }

    /// The chain height this node reports, or `Ok(None)` when it does not know one.
    ///
    /// `Ok(None)` is an honest "no height known" — never height zero, which every block is
    /// trivially above and which would silently satisfy any "is it buried yet" comparison.
    ///
    /// # It is the node's OWN peers that answer this (dig_ecosystem#2790)
    ///
    /// When the corroborated peer reads are attached — which is every production transport — the
    /// height is settled across the peers this node dialled itself
    /// ([`super::quorum::settled_peak`]), and their failure to agree is reported as not knowing.
    ///
    /// The alternative it replaces was worse than it looked: `chia-query`'s router answers a peak
    /// by asking `api.coinset.org` FIRST and consulting this node's peers only when that fails, so
    /// the node's headline chain fact was one HTTPS endpoint's opinion even on a node holding five
    /// peers — and that number divides into the confirmation counts served over RPC. NC-12 asks
    /// for agreement across several concurrently-queried untrusted peers; a single third party is
    /// the shape it exists to prevent.
    ///
    /// A transport with no peer reads — a bare one built by a test — still falls through to the
    /// router. That path is the oracle-first one, and it is documented as such rather than
    /// silently retained: no WALLET read in production takes it.
    ///
    /// The router's peak IS taken in production elsewhere, and by exactly one caller: the
    /// collateral census reads through [`Self::chain_source`], which hands `ChiaQueryProvider`
    /// straight to the router (dig-node#400). Its peak is therefore the oracle-first one described
    /// above — uncorroborated — and it gates that path's reorg-finality check. Extending the
    /// corroborated reads to cover the census's population read is tracked as a sequencing
    /// constraint against the mirror-coin mint; until it lands, no surface may describe the
    /// census's peak as agreed across this node's peers.
    pub async fn peak_height(&self) -> Result<Option<u32>> {
        if let Some(peers) = &self.peer_reads {
            return Ok(peers.peak_height().await);
        }
        self.client()
            .await?
            .peak_height_opt()
            .await
            .map_err(|e| Error::internal(format!("peak-height read failed: {e}")))
    }

    /// The node's own Chia peer tier: full nodes HELD, and the peak they announced
    /// (dig_ecosystem#2806).
    ///
    /// # This DIALS NOTHING
    ///
    /// It reports the client that already exists and answers [`ChainPeerTier::UNOBSERVABLE`] when
    /// none does. Building one here would make merely ASKING a node how many peers it holds the
    /// act that makes it hold them — so a status call would dial mainnet, including from a test
    /// harness that exists precisely so nothing does.
    ///
    /// A node that should hold peers gets them from [`Self::warm`] at start-up instead, which is
    /// the honest arrangement: the peers are held because the node is running, not because
    /// somebody looked.
    ///
    /// # Why both numbers come from the same client
    ///
    /// They describe one tier, and a count from one place beside a peak from another can disagree
    /// — five peers reporting a height they never sent. `peer_peak_height` is also the ONLY peak
    /// that evidences a live light client: [`Self::peak_height`] answers "what is the chain's
    /// peak" and consults the public oracle first, so its figure is a third party's view of the
    /// chain even on a node holding five peers.
    ///
    /// Unbuildable is [`ChainPeerTier::UNOBSERVABLE`], never a zero count: a node that could not
    /// look has not looked and found none.
    pub async fn peer_tier(&self) -> ChainPeerTier {
        let raw = match self.sources.existing_client().await {
            Some(client) => ChainPeerTier {
                peer_count: u32::try_from(client.peer_count().await).ok(),
                peak_height: client.peer_peak_height().await,
            },
            None => ChainPeerTier::UNOBSERVABLE,
        };
        self.observe_peer_liveness_at(Instant::now(), raw)
    }

    /// Fold a raw tier reading through this transport's liveness record, at a caller-supplied
    /// instant.
    ///
    /// [`peer_tier`](Self::peer_tier) is this with `Instant::now()` and the reading the client
    /// gave, and it is written as a two-line composition so that a miswiring would be visible in
    /// the one place it could occur. The instant is a parameter because the window is three
    /// minutes long and a test that waits three minutes is a test nobody runs.
    pub(crate) fn observe_peer_liveness_at(
        &self,
        now: Instant,
        raw: ChainPeerTier,
    ) -> ChainPeerTier {
        self.peer_liveness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(now, raw)
    }

    /// Connect the peer tier, so the node HOLDS Chia peers because it is running
    /// (dig_ecosystem#2806).
    ///
    /// Returns whether the transport now has a client. The node calls this in the background at
    /// start-up; nothing else needs it, because every chain read builds the client anyway.
    ///
    /// Separate from the lazy build in [`Self::client`] rather than replacing it: the laziness is
    /// there so a node with the wallet surfaces switched off makes no chain call, and this is the
    /// caller that decides such a node exists. A node meant to be a light client asks for its
    /// peers up front; a node that is not, never calls this and dials nothing.
    ///
    /// It is deliberately retried by the caller rather than here: "connect once at boot" makes a
    /// node that started before its network permanently peerless, and a node reporting zero peers
    /// forever because of a transient DNS failure at start-up is indistinguishable from one that
    /// is broken.
    ///
    /// # A client that connected NO peers is not warm, and is discarded
    ///
    /// `ChiaQuery::new` succeeds with an empty pool on purpose — its coinset tier needs no peer,
    /// so a peer-tier problem must not deny a reader the fallback that exists for it. That makes
    /// "the client built" the wrong test here: a node offline at start-up would build an empty
    /// client, report success, and end the retry loop holding nothing, which is exactly the
    /// permanently-peerless outcome the retry exists to prevent.
    ///
    /// So an empty pool is dropped rather than kept. The pool refills only from inside a request
    /// (`try_refill` runs when one selects a peer), so a cached empty client would still be empty
    /// on the next attempt however many times it is retried — discarding it is what makes the
    /// next attempt actually redial. It is replaced only if it is still the client this call
    /// built, so a client somebody else has since built is never thrown away.
    pub async fn warm(&self) -> bool {
        let Ok(client) = self.client().await else {
            return false;
        };
        if client.peer_count().await > 0 {
            return true;
        }
        self.sources.discard_if_current(&client).await;
        false
    }

    /// Push an ALREADY-SIGNED bundle.
    ///
    /// The node never signs and is never given anything it could sign with (§908): this takes a
    /// complete bundle and relays it. A mempool refusal comes back as `Ok(PushOutcome)` with
    /// `accepted: false`; an unreachable network is an `Err`.
    pub async fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome> {
        let status = self
            .client()
            .await?
            .push_tx(&to_query_bundle(bundle)?)
            .await
            .map_err(|e| Error::internal(format!("push failed to reach a mempool: {e}")))?;

        Ok(if status.success {
            PushOutcome {
                accepted: true,
                transaction_id: Some(hex::encode(bundle.name())),
                rejection: None,
            }
        } else {
            PushOutcome {
                accepted: false,
                transaction_id: None,
                rejection: Some(status.status),
            }
        })
    }
}

#[async_trait]
impl SignedBundlePusher for ChainTransport {
    async fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome> {
        ChainTransport::push(self, bundle).await
    }
}

#[async_trait]
impl ChainFallback for ChainTransport {
    async fn peer_tier(&self) -> ChainPeerTier {
        ChainTransport::peer_tier(self).await
    }

    async fn peak_height(&self) -> Result<Option<u32>> {
        ChainTransport::peak_height(self).await
    }

    async fn coin_records_by_puzzle_hashes(&self, phs: &[String]) -> Result<Vec<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_records_by_puzzle_hashes(phs)
            .await
    }

    async fn coin_records_by_hints(&self, hints: &[String]) -> Result<Vec<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_records_by_hints(hints)
            .await
    }

    async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
        if let Some(peers) = &self.peer_reads {
            return peers.coin_record_by_id(coin_id).await;
        }
        CoinsetFallback::new(self.client().await?)
            .coin_record_by_id(coin_id)
            .await
    }

    async fn coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
        if let Some(peers) = &self.peer_reads {
            return peers.coin_spend(coin_id).await;
        }
        CoinsetFallback::new(self.client().await?)
            .coin_spend(coin_id)
            .await
    }

    /// Served by the peer-read cache when there is one; a transport without peer reads holds no
    /// cache and truthfully offers nothing for free (dig_ecosystem#3044).
    async fn cached_coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
        match &self.peer_reads {
            Some(peers) => peers.cached_coin_record_by_id(coin_id).await,
            None => Ok(None),
        }
    }

    /// The spend-side counterpart, on the same terms.
    async fn cached_coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
        match &self.peer_reads {
            Some(peers) => peers.cached_coin_spend(coin_id).await,
            None => Ok(None),
        }
    }

    async fn coin_records_by_parent(&self, parent_coin_id: &str) -> Result<Vec<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_records_by_parent(parent_coin_id)
            .await
    }

    /// `true`: this tier CAN reach a chain, so a read that fails does so as an honest error rather
    /// than being routed away as "there was nothing to ask".
    ///
    /// The distinction the caller draws off this flag is "is there a source at all", not "is the
    /// network up right now". Reporting `false` for a momentary outage would send an unreachable
    /// chain down the no-source path, where it reads as a permanent capability gap and tells the
    /// user to change their node instead of to try again.
    fn is_live(&self) -> bool {
        true
    }
}

// DELIBERATELY NOT a `Broadcaster` (dig_ecosystem#2376 review).
//
// `Broadcaster` is the node's OWN-SPEND path: attaching one turns on `auto_submit` and
// `submit_transaction` for the node's custodied key, which is the decision
// `DIG_WALLET_ENABLE_LIVE_BROADCAST` owns. An unused `impl Broadcaster for ChainTransport` sat here
// and made a one-line `.with_broadcaster(chain.clone())` compile, pass every test, and silently
// enable node-custodied sending on a default install.
//
// A `Broadcaster` is reachable from the transport, but only by NAME, through
// [`ChainTransport::broadcaster`] — a visible line in a diff that a caller has to write on purpose.
// The `impl` is what made it ambient; asking for one is not. Its other route out is as a
// `SignedBundlePusher`, whose contract is a bundle somebody already signed.

/// Decode a hex-encoded, already-signed spend bundle.
///
/// Rejects anything that is not a complete `SpendBundle` in chia's `Streamable` form. Kept PURE and
/// separate from the push so a malformed bundle is an INVALID_PARAMS answer the caller can act on,
/// never a network error that reads as "try again" for a bundle that will never parse.
pub fn decode_signed_bundle(signed_bundle_hex: &str) -> Result<SpendBundle> {
    use chia_traits::Streamable;

    let trimmed = signed_bundle_hex
        .strip_prefix("0x")
        .unwrap_or(signed_bundle_hex);
    let bytes = hex::decode(trimmed)
        .map_err(|e| Error::api(format!("signed_bundle_hex is not hex: {e}")))?;
    SpendBundle::from_bytes(&bytes).map_err(|e| {
        Error::api(format!(
            "signed_bundle_hex is not a streamable SpendBundle: {e}"
        ))
    })
}

/// Re-encode a bundle to the hex form [`decode_signed_bundle`] accepts. Used by the round-trip
/// tests and by any caller that needs to hand the same bytes on.
pub fn encode_signed_bundle(bundle: &SpendBundle) -> Result<String> {
    use chia_traits::Streamable;

    bundle
        .to_bytes()
        .map(hex::encode)
        .map_err(|e| Error::internal(format!("bundle serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Bytes32, Coin, CoinSpend, Program};

    /// A minimal but REAL signed bundle: one coin spend and an aggregate signature slot.
    fn a_bundle() -> SpendBundle {
        let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 1_000);
        let spend = CoinSpend::new(coin, Program::from(vec![0x01]), Program::from(vec![0x80]));
        SpendBundle::new(vec![spend], Default::default())
    }

    /// **The hex form round-trips.** Pinned because the wire carries hex, not a struct: a bundle
    /// that re-encodes to different bytes would be pushed as a DIFFERENT transaction than the one
    /// the wallet signed, and its signature would no longer cover it.
    #[test]
    fn a_bundle_survives_the_hex_form_byte_for_byte() {
        let bundle = a_bundle();
        let hex = encode_signed_bundle(&bundle).expect("encode");
        let decoded = decode_signed_bundle(&hex).expect("decode");
        assert_eq!(decoded, bundle);
        assert_eq!(encode_signed_bundle(&decoded).expect("re-encode"), hex);
    }

    /// A `0x` prefix is tolerated, because half the Chia ecosystem emits one.
    #[test]
    fn a_zero_x_prefixed_bundle_decodes_identically() {
        let hex = encode_signed_bundle(&a_bundle()).expect("encode");
        assert_eq!(
            decode_signed_bundle(&format!("0x{hex}")).expect("decode"),
            decode_signed_bundle(&hex).expect("decode")
        );
    }

    /// **Garbage is INVALID_PARAMS, not a network failure.** The distinction is the caller's
    /// remedy: a malformed bundle will never succeed however many times it is retried.
    ///
    /// The two fixtures separate the two ways a bundle can be wrong — not hex at all, and
    /// well-formed hex that is not a bundle — because a decoder that only checked hex would pass
    /// the first and be caught by the second.
    #[test]
    fn a_malformed_bundle_is_rejected_before_any_network_call() {
        for bad in ["zzzz", "deadbeef"] {
            let err = decode_signed_bundle(bad).expect_err("must refuse");
            assert!(
                format!("{err}").contains("signed_bundle_hex"),
                "the error must name the offending parameter: {err}"
            );
        }
    }

    /// **An unbuilt transport holds an UNKNOWN number of peers, not zero — and asking does not
    /// make it dial.**
    ///
    /// Both halves matter and neither is cosmetic. `Some(0)` would tell a user their machine is
    /// connected to no Chia peers, which is a claim about their machine that nobody measured; the
    /// node shows this number as evidence it is a light client, so an unmeasured default is the
    /// one thing it must never be. And a version that built the client here would turn a status
    /// call into a mainnet dial — from this very test process among others.
    ///
    /// Asserted through the public surface, so it stays true of what a caller can observe.
    #[tokio::test]
    async fn an_unbuilt_transport_reports_an_unknown_peer_count_without_dialing() {
        let transport = ChainTransport::new();

        assert_eq!(transport.peer_tier().await, ChainPeerTier::UNOBSERVABLE);
        assert!(
            transport.sources.existing_client().await.is_none(),
            "asking for the peer tier must not be what makes the node hold peers"
        );
    }

    /// An arbitrary coin read served from the peer-read cache dials NOTHING (dig_ecosystem#3032).
    ///
    /// The assertion that carries the weight is the second one. "The read returned the coin" is
    /// satisfied identically by a transport that consulted the third-party oracle first and only
    /// then reached the cache — so the test also asserts that no chain client was ever built.
    /// That is what makes the ORDERING observable rather than inferred from an equal value, and it
    /// is the whole point of the change: the oracle is replaced, not merely preceded.
    #[tokio::test]
    async fn a_cached_arbitrary_coin_read_is_served_without_building_a_chain_client() {
        let db = crate::sage::db::WalletDb::open_in_memory().await.unwrap();
        // The id is DERIVED from the three fields below rather than picked, because the cached
        // read path re-checks that a row's fields hash to the key it is stored under
        // (dig_ecosystem#3035). A picked id would make this a row that could not exist on chain.
        let hex32 = |h: &str| -> chia_protocol::Bytes32 {
            let bytes: [u8; 32] = hex::decode(h).unwrap().try_into().unwrap();
            chia_protocol::Bytes32::from(bytes)
        };
        let coin_id = hex::encode(
            chia_protocol::Coin {
                parent_coin_info: hex32(&"cd".repeat(32)),
                puzzle_hash: hex32(&"ef".repeat(32)),
                amount: 1234,
            }
            .coin_id(),
        );
        db.put_chain_read(
            &crate::sage::db::ChainReadCacheRow {
                coin_id: coin_id.clone(),
                parent_coin_info: "cd".repeat(32),
                puzzle_hash: "ef".repeat(32),
                amount: "1234".into(),
                created_height: Some(9_000_000),
                // SPENT, so the entry is immutable and usable however long ago it was written — the
                // test therefore does not depend on when it runs.
                spent_height: Some(9_000_050),
                created_timestamp: None,
                spent_timestamp: None,
                cached_at: 0,
            },
            0,
        )
        .await
        .unwrap();

        let transport = ChainTransport::new().with_peer_reads(db);
        let answer = ChainFallback::coin_record_by_id(&transport, &coin_id)
            .await
            .unwrap()
            .expect("the cached coin must be served");

        assert_eq!(answer.amount, 1234);
        assert_eq!(answer.spent_height, Some(9_000_050));
        assert!(
            transport.sources.existing_client().await.is_none(),
            "an arbitrary coin read must no longer route through the third-party oracle"
        );
    }

    /// The transport starts with NO client, so merely constructing one dials nothing.
    ///
    /// Asserted through the public surface rather than by reading the field, so it stays true of
    /// what a caller can observe: a node that never serves a wallet read makes no chain call.
    #[tokio::test]
    async fn a_new_transport_holds_no_client_until_it_is_used() {
        let transport = ChainTransport::new();
        assert!(transport.sources.existing_client().await.is_none());
    }
}

#[cfg(test)]
mod corroborated_peak_tests {
    //! The height the node reports is its OWN peers' settled view, not a third party's
    //! (dig_ecosystem#2790).
    //!
    //! # What these catch that the previous code did not
    //!
    //! `peak_height` used to call `chia-query`'s router, which asks `api.coinset.org` FIRST and
    //! consults this node's peers only when that fails. Under the old code every assertion here
    //! would have been decided by one HTTPS endpoint: the collapsed-round cases would have
    //! returned a number rather than refusing, and all of them would have built a chain client.
    //!
    //! So the load-bearing assertion in each test is the SECOND one — that no client was ever
    //! built. "The value came back `None`" is satisfied identically by a transport that consulted
    //! the oracle, failed to reach it, and reported nothing; asserting that the oracle was never
    //! reached for is what makes the placement observable rather than inferred from an equal
    //! value.

    use super::*;
    use crate::sage::peer_reads::{CoinPeer, PeerCorroboratedReads, PeerSample};
    use crate::sage::quorum::{PeakClaim, SETTLED_LAG};
    use async_trait::async_trait;
    use chia_protocol::Bytes32;

    /// A peer that announces one tip and answers no coin question.
    ///
    /// Coin silence isolates the peak round: nothing here can pass because of a coin answer.
    struct PeakOnlyPeer {
        id: String,
        claim: Option<PeakClaim>,
    }

    #[async_trait]
    impl CoinPeer for PeakOnlyPeer {
        fn id(&self) -> String {
            self.id.clone()
        }

        async fn peak_claim(&self) -> Option<PeakClaim> {
            self.claim
        }

        async fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<FallbackCoin>> {
            Err(Error::internal("this peer answers no coin questions"))
        }

        async fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<FallbackCoinSpend>> {
            Err(Error::internal("this peer answers no coin questions"))
        }
    }

    /// A draw of peers claiming the given heights, each with a distinct id.
    struct ScriptedTips(Vec<u32>);

    #[async_trait]
    impl PeerSample for ScriptedTips {
        async fn draw(&self) -> Vec<Arc<dyn CoinPeer>> {
            self.0
                .iter()
                .enumerate()
                .map(|(i, height)| {
                    let mut hash = [0u8; 32];
                    hash[..4].copy_from_slice(&height.to_be_bytes());
                    Arc::new(PeakOnlyPeer {
                        id: format!("10.0.0.{i}:8444"),
                        claim: Some(PeakClaim {
                            height: *height,
                            header_hash: Bytes32::from(hash),
                        }),
                    }) as Arc<dyn CoinPeer>
                })
                .collect()
        }
    }

    async fn transport_over(tips: Vec<u32>) -> ChainTransport {
        let db = crate::sage::db::WalletDb::open_in_memory().await.unwrap();
        ChainTransport::new().with_peer_reads_arc(Arc::new(PeerCorroboratedReads::new(
            Arc::new(ScriptedTips(tips)),
            db,
        )))
    }

    /// The control: agreeing peers produce a height, and still nothing dials an oracle.
    ///
    /// Without this every test below is satisfied by a `peak_height` that returns `None`
    /// unconditionally, which would pass the refusals and break the node.
    #[tokio::test]
    async fn agreeing_peers_give_the_node_a_height_without_asking_a_third_party() {
        let transport = transport_over(vec![9_000_000; 4]).await;
        let reported = transport.peak_height().await.unwrap();

        // The PLACEMENT assertion goes first, deliberately. Asserted after the value it would
        // never be REACHED on a regression: the value assertion fires, the placement one is never
        // evaluated, and the property it exists to pin stays unproven while the test still turns
        // red for a reason that looks convincing. Measured — all three of these tests originally
        // failed their revert-proof on the value line and proved nothing about the oracle.
        assert!(
            transport.sources.existing_client().await.is_none(),
            "the node's own peers answered, and it consulted the public oracle anyway"
        );
        assert_eq!(reported, Some(9_000_000 - SETTLED_LAG));
    }

    /// A round that collapses to ONE voice reports no height, and does NOT fall through to the
    /// oracle to find one.
    ///
    /// Falling through is the tempting repair and it is the defect: it would let a single HTTPS
    /// endpoint decide the height precisely when the peers failed to agree — which is the
    /// single-source dependency NC-12 exists to remove, arriving at exactly the moment it matters.
    #[tokio::test]
    async fn a_single_peer_yields_no_height_and_no_fallback_to_the_oracle() {
        let transport = transport_over(vec![9_000_000]).await;
        let reported = transport.peak_height().await.unwrap();

        assert!(
            transport.sources.existing_client().await.is_none(),
            "the peers did not agree and the node asked a third party instead, which is the \
             single source this change removes"
        );
        assert_eq!(
            reported, None,
            "one peer was allowed to tell this node where the chain is"
        );
    }

    /// A split sample is an unknown height, reported as unknown — again without an oracle read.
    #[tokio::test]
    async fn a_split_sample_yields_no_height_and_no_fallback_to_the_oracle() {
        let transport = transport_over(vec![9_000_000, 9_000_000, 8_000_000, 8_000_000]).await;
        let reported = transport.peak_height().await.unwrap();

        assert!(
            transport.sources.existing_client().await.is_none(),
            "a partition was resolved by asking a third party which side to believe"
        );
        assert_eq!(reported, None);
    }

    /// **Every oracle-first `ChainTransport` in this file is one of two NAMED constructors, and
    /// the list is closed.**
    ///
    /// A transport built with `peer_reads: None` answers [`ChainTransport::peak_height`] from
    /// `chia-query`'s router, whose first move is to ask `api.coinset.org` — one third party
    /// deciding the node's headline chain fact. Exactly two constructors are allowed to produce
    /// that shape and neither is reachable from production: `new`, which every real caller
    /// immediately chains `with_peer_reads` onto, and the `#[cfg(test)]` `with_client`.
    ///
    /// This guard exists because `with_sources` was a THIRD one (dig-node#360) — `pub`, `#[must_use]`,
    /// named as though it were the ordinary way to build a transport over the node's own fabric,
    /// and silently oracle-first. It had no callers, so nothing failed; it was deleted, and this is
    /// what makes the deletion durable rather than a one-time tidy-up.
    ///
    /// **Fail-closed by construction:** a new site is a FAILURE, never a silent pass. Adding a
    /// legitimate one means naming it here, which is the review moment the ticket asks for.
    ///
    /// The needle is the struct-literal FIELD form (trailing comma), not the prose form, so the
    /// doc comments that discuss this shape are not counted as sites. And it is assembled at run
    /// time from two fragments so this test cannot match ITSELF —
    /// a source-scanning guard that finds its own needle reports a site that does not exist and
    /// passes for the wrong reason.
    #[test]
    fn the_oracle_first_constructors_are_a_closed_enumeration_of_two() {
        const ALLOWED: [&str; 2] = ["new", "with_client"];

        let source = include_str!("chain.rs");
        let needle = ["peer_reads", ": None,"].concat();

        let mut found: Vec<&str> = Vec::new();
        for (offset, _) in source.match_indices(&needle) {
            // Walk back to the nearest `fn ` and read the identifier that follows it. The nearest
            // preceding `fn` is the enclosing one for every construction site in this file.
            let before = &source[..offset];
            let fn_at = before
                .rfind("fn ")
                .expect("a construction site outside any function");
            let name = before[fn_at + 3..]
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .expect("a `fn` with no name");
            found.push(name);
        }

        assert!(
            !found.is_empty(),
            "the scan matched nothing, so it proves nothing — the needle no longer describes how \
             an oracle-first transport is written, and this guard has gone vacuous"
        );

        let unlisted: Vec<&&str> = found.iter().filter(|n| !ALLOWED.contains(n)).collect();
        assert!(
            unlisted.is_empty(),
            "these constructors build an oracle-first ChainTransport and are not on the closed \
             list {ALLOWED:?}: {unlisted:?} — a transport whose peak_height is one HTTPS \
             endpoint's opinion (NC-12, dig-node#360). Attach peer reads, or add the name here \
             deliberately."
        );
    }
    // -----------------------------------------------------------------------
    // The held-peer count is a measurement, not a belief nothing challenged (#351)
    // -----------------------------------------------------------------------

    /// A raw tier reading as the pool would give it.
    fn tier(peer_count: Option<u32>, peak_height: Option<u32>) -> ChainPeerTier {
        ChainPeerTier {
            peer_count,
            peak_height,
        }
    }

    /// **Proves (#351):** the exact fleet observation. With the held count frozen at 5 and the
    /// peers' peak frozen beside it, the reported count becomes UNKNOWN once the liveness window
    /// passes — and the CONTROL in the same test, a pool whose peak keeps advancing, still reports
    /// 5 at the very same instant.
    ///
    /// **The control is what makes this discriminating.** "The count goes unknown after three
    /// minutes" is satisfied identically by an implementation that always reports unknown, or that
    /// expires on a timer regardless of evidence. Only the pair distinguishes *stale* from *old*,
    /// and staleness is the defect: on the #3159 fleet the node reported `chia_peer_count: 5` for
    /// 180 s while every Chia peer was blocked and it could reach zero.
    ///
    /// Both transports see the SAME held count and the SAME elapsed time. The one difference is
    /// whether anything alive was heard from.
    #[test]
    fn a_frozen_peer_tier_goes_unknown_while_a_live_one_keeps_reporting_its_count() {
        let now = Instant::now();
        let dead = ChainTransport::new();
        let live = ChainTransport::new();

        assert_eq!(
            dead.observe_peer_liveness_at(now, tier(Some(5), Some(9_196_851))),
            tier(Some(5), Some(9_196_851)),
            "a first sighting is itself an observation"
        );
        assert_eq!(
            live.observe_peer_liveness_at(now, tier(Some(5), Some(9_196_851))),
            tier(Some(5), Some(9_196_851))
        );

        let later = now + PEER_LIVENESS_WINDOW + Duration::from_secs(1);

        assert_eq!(
            dead.observe_peer_liveness_at(later, tier(Some(5), Some(9_196_851))),
            tier(None, Some(9_196_851)),
            "nothing has been heard from the held peers, so how many are held is unknown"
        );
        assert_eq!(
            live.observe_peer_liveness_at(later, tier(Some(5), Some(9_196_860))),
            tier(Some(5), Some(9_196_860)),
            "a peak that advanced is a held session delivering, so the count still stands"
        );
    }

    /// **Proves:** an unknown count is `None`, never `Some(0)`.
    ///
    /// Stated separately because the two are the same shape to a careless reader and opposite
    /// claims to an operator: `0` says "your machine is connected to no Chia peers", which is a
    /// measurement nobody took, and it is the exact failure the surrounding `ChainPeerTier` doc
    /// forbids field by field.
    #[test]
    fn an_unknown_held_count_is_never_reported_as_a_measured_zero() {
        let transport = ChainTransport::new();
        let now = Instant::now();

        transport.observe_peer_liveness_at(now, tier(Some(5), Some(100)));
        let stale = transport.observe_peer_liveness_at(
            now + PEER_LIVENESS_WINDOW + Duration::from_secs(1),
            tier(Some(5), Some(100)),
        );

        assert_eq!(stale.peer_count, None);
        assert_ne!(stale.peer_count, Some(0), "unknown is not a measured none");
    }

    /// **Proves:** the window is `PEER_LIVENESS_WINDOW`, pinned from BOTH sides.
    ///
    /// Exactly at the window the count still stands; one millisecond past it, it does not. A bound
    /// tested only from one side can only confirm itself — an implementation expiring instantly, or
    /// one expiring an hour late, passes a test that checks a single point.
    #[test]
    fn the_liveness_window_holds_at_its_bound_and_lapses_one_tick_past_it() {
        let now = Instant::now();
        let at_bound = ChainTransport::new();
        let past_bound = ChainTransport::new();

        at_bound.observe_peer_liveness_at(now, tier(Some(5), Some(100)));
        past_bound.observe_peer_liveness_at(now, tier(Some(5), Some(100)));

        assert_eq!(
            at_bound
                .observe_peer_liveness_at(now + PEER_LIVENESS_WINDOW, tier(Some(5), Some(100)))
                .peer_count,
            Some(5),
            "at the bound the count is still believable"
        );
        assert_eq!(
            past_bound
                .observe_peer_liveness_at(
                    now + PEER_LIVENESS_WINDOW + Duration::from_millis(1),
                    tier(Some(5), Some(100)),
                )
                .peer_count,
            None,
            "one tick past it, it is not"
        );
    }

    /// **Proves:** the held count CHANGING is itself a sign of life, independently of the peak.
    ///
    /// A count moves only when the pool admits or ejects, which are real events on real sockets. So
    /// a pool losing peers — `5 -> 4` — is observably alive even while the chain is quiet, and must
    /// not be reported as unknown merely because no new peak arrived.
    ///
    /// This is the assertion that fails if the freshness test is narrowed to the peak alone.
    #[test]
    fn a_change_in_the_held_count_is_itself_a_sign_of_life() {
        let now = Instant::now();
        let transport = ChainTransport::new();

        transport.observe_peer_liveness_at(now, tier(Some(5), Some(100)));

        // Well past the window, but the pool visibly ejected a peer at this instant.
        let later = now + PEER_LIVENESS_WINDOW + Duration::from_secs(60);
        assert_eq!(
            transport
                .observe_peer_liveness_at(later, tier(Some(4), Some(100)))
                .peer_count,
            Some(4),
            "an ejection is an observation of the pool acting on real sockets"
        );
    }

    /// **Proves:** unknown is RECOVERABLE. A node whose peers come back reports a count again
    /// rather than staying dark, so the field is a live reading in both directions.
    ///
    /// Without this a single quiet stretch would latch the surface into permanent uncertainty,
    /// which is a different lie in the other direction.
    #[test]
    fn a_count_that_lapsed_into_unknown_is_reported_again_once_the_peers_speak() {
        let now = Instant::now();
        let transport = ChainTransport::new();

        transport.observe_peer_liveness_at(now, tier(Some(5), Some(100)));
        let lapsed = now + PEER_LIVENESS_WINDOW + Duration::from_secs(1);
        assert_eq!(
            transport
                .observe_peer_liveness_at(lapsed, tier(Some(5), Some(100)))
                .peer_count,
            None
        );

        assert_eq!(
            transport
                .observe_peer_liveness_at(
                    lapsed + Duration::from_secs(19),
                    tier(Some(5), Some(101))
                )
                .peer_count,
            Some(5),
            "the peers spoke again, so the count is a measurement again"
        );
    }

    /// **Proves the WIRING:** `peer_tier` routes through the liveness record rather than reading
    /// the pool and reporting it.
    ///
    /// A unit test of `observe` alone cannot see whether anything calls it, and a policy nothing
    /// calls is indistinguishable from no policy. The proof uses the one observable side effect
    /// available without a network: an unobservable reading RESETS the record, so calling
    /// `peer_tier()` on an unbuilt transport must make a subsequent reading count as a FIRST
    /// sighting even though the window has long since passed.
    ///
    /// If `peer_tier` did not touch the record, the aged confirmation from before would survive and
    /// the final count would come back `None`.
    #[tokio::test]
    async fn peer_tier_folds_its_reading_through_the_liveness_record() {
        let transport = ChainTransport::new();
        let now = Instant::now();

        transport.observe_peer_liveness_at(now, tier(Some(5), Some(100)));

        assert_eq!(
            transport.peer_tier().await,
            ChainPeerTier::UNOBSERVABLE,
            "no client exists, so there is nothing to measure"
        );

        assert_eq!(
            transport
                .observe_peer_liveness_at(
                    now + PEER_LIVENESS_WINDOW + Duration::from_secs(600),
                    tier(Some(5), Some(100)),
                )
                .peer_count,
            Some(5),
            "peer_tier reset the record, so this is a first sighting rather than a stale one"
        );
    }

    /// **Proves:** a client going away resets the record rather than ageing it, and reports
    /// unknown while it is gone.
    ///
    /// The next client is a different set of sockets. Carrying the previous one's confirmation
    /// across the gap would let a freshly built pool inherit an expiry it never earned — and,
    /// worse, would let a pool that has just connected be reported as unknown.
    #[test]
    fn a_client_going_away_resets_the_record_rather_than_ageing_it() {
        let now = Instant::now();
        let transport = ChainTransport::new();

        transport.observe_peer_liveness_at(now, tier(Some(5), Some(100)));
        assert_eq!(
            transport.observe_peer_liveness_at(now, ChainPeerTier::UNOBSERVABLE),
            ChainPeerTier::UNOBSERVABLE
        );

        assert_eq!(
            transport
                .observe_peer_liveness_at(
                    now + PEER_LIVENESS_WINDOW + Duration::from_secs(1),
                    tier(Some(3), Some(100)),
                )
                .peer_count,
            Some(3),
            "a rebuilt pool is measured from its own first sighting"
        );
    }
}
