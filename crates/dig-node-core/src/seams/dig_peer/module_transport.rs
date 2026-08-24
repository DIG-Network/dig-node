//! [`NatModuleTransport`] — the production [`ModuleTransport`] for the whole-`.dig`-module pull (#1576).
//!
//! [`dig_download::ModuleDownloader`] plans and attributes the pull; this adapter is the only part of
//! it that touches the network. It answers the engine's two calls —
//! [`get_module_info`](ModuleTransport::get_module_info) and
//! [`fetch_module_range`](ModuleTransport::fetch_module_range) — over the node's real peer client
//! ([`DigPeer`]) on the FULL NAT-traversal ladder, mirroring `dig-download`'s own
//! `NatRangeTransport` for the resource leg.
//!
//! # Resolving a `peer_id` back to an address
//!
//! The engine hands this transport a bare 64-hex `provider_peer_id` — it has already chosen WHICH
//! holder to ask, and does not re-supply that holder's addresses. So the transport resolves the
//! address itself, from the same two sources the resource leg uses, in the same order (#836): the LIVE
//! connected pool first (a connection-verified address), then DHT discovery (an untrusted, possibly
//! stale advertisement).
//!
//! # Dial order is IPv6-first, and never via string concatenation (§5.2, #1593)
//!
//! Candidates are ordered by [`dig_download::dial_candidates`] and turned into sockets by
//! [`dig_download::candidate_socket`] — the ONE place in the ecosystem that parses a candidate host as
//! an [`IpAddr`](std::net::IpAddr) and CONSTRUCTS the socket address. `format!("{host}:{port}")` +
//! `parse::<SocketAddr>()` is wrong for every IPv6 literal (the grammar needs brackets) and that exact
//! round trip blocked the whole read leg on a host advertising `::ffff:172.31.79.22` (#1593). This
//! adapter therefore never formats an address; it delegates, and every candidate is tried in order so
//! one unusable v6 candidate cannot mask a working v4 one.
//!
//! # Errors carry no peer-supplied text (#1603/#1609)
//!
//! A failure reason is composed from this node's own vocabulary plus the peer's SENTINELLED id. The
//! crate sanitizes at its `Display`/`Debug` layer; embedding raw peer text upstream of that would
//! defeat it, so the reasons here name the step, never echo the answer.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId, ProviderRecord};
use dig_download::{
    candidate_socket, dial_candidates, DownloadError, ModuleTransport, ProviderLocator,
};
use dig_peer::DigPeer;
use dig_rpc_protocol::types::{FetchModuleRangeParams, GetModuleInfoParams, ModuleInfo};

use descriptor_ask::DescriptorAnswer;

use super::pool_locator::ConnectedPool;
use crate::download::BestEffort;

/// The peer-RPC transport the module pull rides.
///
/// Holds the node's mTLS identity + the shared live [`dig_nat::NatRuntime`] (so a dial composes the
/// same hole-punch/relay tiers the rest of the node's dials do), the connected-pool address map, and a
/// discovery locator for holders that are not currently connected.
pub struct NatModuleTransport {
    /// This node's CA-signed mTLS identity, presented on every dial.
    node_cert: Arc<dig_nat::NodeCert>,
    /// Traversal method + timeout selection.
    config: dig_nat::NatConfig,
    /// The network the peers are on (guards a cross-network dial).
    network_id: String,
    /// The live traversal handles: an empty runtime dials Direct only; the node's real runtime unlocks
    /// hole-punch + relay. Shared, so it is the SAME runtime the DHT + resource legs use.
    runtime: Arc<dig_nat::NatRuntime>,
    /// LIVE connection-verified addresses per `peer_id` — consulted FIRST (#836).
    connected: ConnectedPool,
    /// Discovery fallback for a holder that is not currently connected.
    locator: Arc<dyn ProviderLocator>,
    /// Which `(capsule, peer)` pairs have already had a plain descriptor round, so the relay opt-in
    /// is an escalation rather than a default. See [`RelayEscalation`].
    escalation: RelayEscalation,
    /// How much relay waiting each CAPSULE has already cost, so the bound is per pull rather than
    /// per peer. See [`RelayWaitBudget`].
    relay_budget: RelayWaitBudget,
}

impl NatModuleTransport {
    /// Build the transport from the node's identity + the shared live traversal runtime.
    pub fn new(
        node_cert: Arc<dig_nat::NodeCert>,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
        runtime: Arc<dig_nat::NatRuntime>,
        connected: ConnectedPool,
        locator: Arc<dyn ProviderLocator>,
    ) -> Self {
        NatModuleTransport {
            node_cert,
            config,
            network_id: network_id.into(),
            runtime,
            connected,
            locator,
            escalation: RelayEscalation::default(),
            relay_budget: RelayWaitBudget::default(),
        }
    }

    /// Every way to reach `peer_hex` for this capsule, in dial order — the pool's connection-verified
    /// addresses first, then the capsule's DHT provider record, then relay-only reachability by
    /// identity.
    ///
    /// Ordering is deliberate and load-bearing: a live pool address is one this node has already
    /// connected over, while a DHT hint is an untrusted advertisement that may be stale. Leading with
    /// the stale hint is what dead-ended the read leg at HTTP 404 despite a connected, serving holder
    /// (#836).
    async fn dial_targets(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> Result<Vec<(String, dig_nat::PeerTarget)>, DownloadError> {
        let peer = PeerId::from_hex(peer_hex).ok_or_else(|| {
            DownloadError::transport(peer_hex, "malformed provider peer_id (not 64-hex)")
        })?;

        let mut record_addrs: Vec<CandidateAddr> = self.pool_candidates(peer_hex);
        record_addrs.extend(
            self.discovered_candidates(peer_hex, store_id, root)
                .await
                .for_finding(),
        );

        // Order + cap the merged candidate set through dig-download's ONE resolver: IPv6 before IPv4
        // (§5.2), and each socket CONSTRUCTED from a parsed IpAddr rather than a formatted string
        // (#1593). A record is the only shape `dial_candidates` accepts, so build one to order by.
        let record = ProviderRecord::new(
            &module_content_key(store_id, root)?,
            &peer,
            record_addrs,
            u64::MAX,
        );
        let mut targets: Vec<(String, dig_nat::PeerTarget)> = Vec::new();
        for candidate in dial_candidates(&record) {
            match candidate_socket(candidate) {
                Ok(socket) => targets.push((
                    socket.to_string(),
                    dig_nat::PeerTarget::with_addr(peer, socket, self.network_id.clone()),
                )),
                Err(e) => tracing::warn!(
                    peer = %super::serve_log::SafeId::new(peer_hex),
                    error = %e,
                    "module pull: skipping an unusable candidate address"
                ),
            }
        }
        // Relay-only last: reachable purely by identity when no address works.
        targets.push((
            "relay-only".to_string(),
            dig_nat::PeerTarget::relay_only(peer, self.network_id.clone()),
        ));
        Ok(targets)
    }

    /// The peer's LIVE connection-verified addresses from the connected pool (empty if not connected).
    fn pool_candidates(&self, peer_hex: &str) -> Vec<CandidateAddr> {
        let guard = self
            .connected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .get(peer_hex)
            .map(|addrs| {
                addrs
                    .iter()
                    .map(|a| CandidateAddr::direct(a.ip().to_string(), a.port()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The peer's advertised addresses from capsule-granularity discovery.
    ///
    /// Best-effort by design: the live pool addresses this enriches must never be lost to a DHT
    /// error. But the emptiness it can produce is ambiguous — a walk that failed and a walk that
    /// found no advertisement look identical as a bare `Vec` — so the failure is carried out in a
    /// [`BestEffort`] rather than discarded, and a caller can only read an absence from it through
    /// `absence_established()` (dig-node#296).
    async fn discovered_candidates(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> BestEffort<CandidateAddr> {
        let Some(content) = module_content_id(store_id, root) else {
            // A non-canonical id was never asked about, so nothing was found AND nothing failed:
            // this is a genuine "no advertisement", not an unreachable source.
            return BestEffort::found(Vec::new());
        };
        let Ok(records) = self.locator.find_providers(&content).await else {
            return BestEffort::source_failed();
        };
        BestEffort::found(
            records
                .into_iter()
                .find(|r| r.provider_peer_id == peer_hex)
                .map(|r| r.addresses)
                .unwrap_or_default(),
        )
    }

    /// Dial `peer_hex`, trying every candidate in order and reporting the LAST failure with the address
    /// that produced it, so an unreachable candidate is diagnosable rather than an anonymous timeout.
    async fn connect(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> Result<DigPeer, DownloadError> {
        let mut last_error = None;
        for (addr, target) in self.dial_targets(peer_hex, store_id, root).await? {
            match DigPeer::connect_with_runtime(
                &target,
                &self.node_cert,
                &self.config,
                &self.runtime,
            )
            .await
            {
                Ok(peer) => return Ok(peer),
                Err(e) => {
                    tracing::debug!(
                        peer = %super::serve_log::SafeId::new(peer_hex),
                        candidate = %addr,
                        error = %e,
                        "module pull: dial candidate failed; trying the next address"
                    );
                    last_error = Some(format!("dial {addr}: {e}"));
                }
            }
        }
        Err(DownloadError::transport(
            peer_hex,
            last_error.unwrap_or_else(|| "no dialable candidate address".to_string()),
        ))
    }
}

/// Remembers which `(capsule, peer)` pairs have already been asked PLAINLY, so the relay opt-in is a
/// second-pass escalation rather than a property of every request.
///
/// # Why the flag cannot be unconditional
///
/// `ask_with_proxy` used to set `proxy: true` on every module request. That was inert only because
/// the module pull's provider set was holders-only: every peer it asked had announced the capsule, so
/// asking one to relay was asking a holder to serve. Once the warm locator unions the CONNECTED POOL
/// (`NodeContent::warm_provider_locator`), the provider set becomes every connected peer — and an
/// unconditional flag would turn the very first descriptor probe to each of them into a request to
/// **fetch a whole capsule on this node's behalf**, before establishing that no reachable holder
/// exists. On the module path the descriptor probe IS the relay trigger, so the widening that makes
/// a holder reachable would also make every neighbour a courier.
///
/// # What it does NOT change
///
/// This decides WHEN gate (1) of [`module_relay::relay_capsule`](super::module_relay::relay_capsule)
/// is satisfied — never WHETHER it is checked. All three gates (the requestor asked, the operator
/// opted in, the requestor is inside its proxy-class allowance) run exactly as before on the far end.
///
/// # The bound
///
/// Entries are this node's own `(capsule, peer)` choices, so growth tracks this node's own pull
/// activity rather than anything a peer controls. It is still capped: at [`Self::MAX_ENTRIES`] the
/// oldest entry is evicted, which at worst re-sends one plain round for a capsule this node stopped
/// working on long ago.
#[derive(Default)]
struct RelayEscalation {
    /// Insertion-ordered keys, so eviction is FIFO and does not need a timestamp per entry.
    order: std::sync::Mutex<std::collections::VecDeque<String>>,
    /// The same keys as a set, for the O(1) membership test the hot path makes.
    seen: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl RelayEscalation {
    /// The ledger ceiling. Sized to cover the capsules and peers one node works with concurrently
    /// with room to spare; a node past it is pulling from more distinct pairs than any single warm
    /// generation involves.
    const MAX_ENTRIES: usize = 1024;

    /// Whether this node may ask `peer` to RELAY `(store_id, root)` — true once a PLAIN round for
    /// that exact pair has already been sent and did not produce a holder.
    ///
    /// Records the pair as asked, so the answer is `false` the first time and `true` afterwards. It
    /// is deliberately not conditioned on the plain round's OUTCOME: a plain ask that succeeded ends
    /// the pull, so this is only ever consulted again after one that did not.
    fn escalate_for(&self, store_id: &str, root: &str, peer_hex: &str) -> bool {
        let key = format!("{store_id}:{root}:{peer_hex}");
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.contains(&key) {
            return true;
        }
        let mut order = self.order.lock().unwrap_or_else(|p| p.into_inner());
        if order.len() >= Self::MAX_ENTRIES {
            if let Some(oldest) = order.pop_front() {
                seen.remove(&oldest);
            }
        }
        order.push_back(key.clone());
        seen.insert(key);
        false
    }
}

/// How much total relay WAITING one pull of one capsule may spend, across every hop it asks.
///
/// # Why the bound has to be per PULL and not per peer (the amplification the ceiling alone misses)
///
/// [`descriptor_ask::RELAY_MAX_WAIT`] bounds a wait on ONE hop, which is the right instrument for
/// the question it answers — how long to believe a single peer that says it is fetching. It is the
/// wrong instrument for the question the PULL asks, because the pull asks many peers.
///
/// dig-download documents its own worst case as
/// `MAX_DESCRIPTOR_ATTEMPTS × holders × the transport's per-ask timeout`, and this leg raises that
/// last term from the descriptor ladder's 65 s to the relay ceiling's 30 minutes. The warm locator
/// unions the CONNECTED POOL into the provider set, so "holders" is every connected peer rather than
/// every announced one — and ten peers each fabricating one byte of progress per poll would hold a
/// single pull for roughly fifteen hours, with each peer individually inside its ceiling the whole
/// time. Nothing is provably lying; the pull simply never ends.
///
/// **Shrinking the per-hop ceiling is NOT the fix** and would undo dig-node#333: an honest hop
/// relaying a large capsule over a slow link genuinely needs minutes, and that case is the entire
/// reason this path exists. So the per-hop ceiling stays exactly as it is, and the PULL gets its own
/// budget which every hop draws from. One honest hop may still spend the whole of it — the large
/// capsule keeps working — while ten liars share it rather than each being granted it.
const RELAY_WAIT_BUDGET_PER_PULL: std::time::Duration = descriptor_ask::RELAY_MAX_WAIT;

/// Tracks relay waiting already spent per capsule, so the budget above is enforced across the hops
/// of one pull rather than granted afresh to each.
///
/// Keyed by `(store_id, root)` — the generation, which is exactly what one `ModuleDownloader::download`
/// call is about, so the key IS the pull. Entries are this node's own pulls, so growth tracks its own
/// activity and not anything a peer controls; it is still capped, and evicting the oldest merely
/// refreshes the budget of a capsule this node stopped working on long ago.
#[derive(Default)]
struct RelayWaitBudget {
    /// Relay time already spent per capsule.
    spent: std::sync::Mutex<std::collections::HashMap<String, std::time::Duration>>,
    /// Insertion order, so eviction is FIFO without a timestamp per entry.
    order: std::sync::Mutex<std::collections::VecDeque<String>>,
}

impl RelayWaitBudget {
    /// The ledger ceiling, matching [`RelayEscalation::MAX_ENTRIES`]: both track this node's own
    /// concurrent pulls, so one bound serves both.
    const MAX_ENTRIES: usize = 1024;

    /// The capsule's key in this ledger.
    fn key(store_id: &str, root: &str) -> String {
        format!("{store_id}:{root}")
    }

    /// How much of the pull's relay-wait budget is LEFT for `(store_id, root)`.
    ///
    /// Saturating, so an over-charge (a wait that overran its own ceiling by a scheduling margin)
    /// yields zero rather than wrapping into a fresh budget.
    fn remaining(&self, store_id: &str, root: &str) -> std::time::Duration {
        let spent = self
            .spent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&Self::key(store_id, root))
            .copied()
            .unwrap_or(std::time::Duration::ZERO);
        RELAY_WAIT_BUDGET_PER_PULL.saturating_sub(spent)
    }

    /// Charge `waited` against `(store_id, root)`.
    ///
    /// A zero charge records nothing: the overwhelming majority of descriptor asks involve no relay
    /// at all, and an entry per ask would evict the entries that matter.
    fn charge(&self, store_id: &str, root: &str, waited: std::time::Duration) {
        if waited.is_zero() {
            return;
        }
        let key = Self::key(store_id, root);
        let mut spent = self.spent.lock().unwrap_or_else(|p| p.into_inner());
        let mut order = self.order.lock().unwrap_or_else(|p| p.into_inner());
        if !spent.contains_key(&key) {
            if order.len() >= Self::MAX_ENTRIES {
                if let Some(oldest) = order.pop_front() {
                    spent.remove(&oldest);
                }
            }
            order.push_back(key.clone());
        }
        let entry = spent.entry(key).or_insert(std::time::Duration::ZERO);
        *entry = entry.saturating_add(waited);
    }
}

/// The largest framed JSON body accepted for a module DESCRIPTOR answer.
///
/// The generic peer-request reader ([`crate::peer::read_framed`]) caps at 64 KiB, which is right for
/// a REQUEST and too small for this RESPONSE: a descriptor declares one 32-byte hash and one length
/// per chunk, so the largest permitted module runs to a few hundred kilobytes of JSON. This is still
/// a hard bound — a peer cannot make this node buffer an arbitrary body by declaring one.
const MAX_DESCRIPTOR_FRAME: usize = 8 * 1024 * 1024;

/// Ask `stream` a whole-`.dig` question as a framed JSON-RPC request, declaring whether this node is
/// asking the far end to RELAY the capsule on its behalf (dig-node#276).
///
/// # Why this node frames the request itself instead of calling dig-peer's typed method
///
/// `GetModuleInfoParams` / `FetchModuleRangeParams` live in `dig-rpc-protocol` and carry no `proxy`
/// field. Adding one is a level-00 crate change and a release-first cascade through `dig-peer` ->
/// `dig-download` -> this repo, for a single boolean on a request this repo both sends and serves.
/// dig-peer's own [`DigPeer::open_stream`] is the documented escape hatch for exactly this — a
/// consumer carrying its own wire shape over the authenticated mux — and the typed method it replaces
/// is itself only a `build_request` plus a framed write over that same stream.
///
/// The flag is ADDITIVE: a peer that does not implement the relay ignores an unknown params key and
/// answers precisely as it does today, so this is safe to send to every holder unconditionally.
async fn ask_with_proxy(
    stream: &mut dig_nat::PeerStream,
    method: dig_rpc_protocol::Method,
    mut params: serde_json::Value,
    proxy: bool,
) -> std::io::Result<()> {
    declare_proxy(&mut params, proxy);
    crate::peer::write_framed(
        stream,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method.name(),
            "params": params,
        }),
    )
    .await
}

/// Write the relay opt-in into a module request's params.
///
/// A whole-`.dig` download escalates to ONION mode on a SECOND pass: if no reachable peer holds the
/// capsule, we would rather a hop fetched it for us than be told "not found" by a peer sitting one
/// hop from someone who has it. The FIRST pass is plain — see [`RelayEscalation`]. Individual
/// RESOURCE requests are unaffected and still default to DIRECT (NC-4).
///
/// The flag is ALWAYS written, including `false`: absent means "unspecified" to a reader that has
/// its own default, and this node has a specific instruction to give on every request. Extracted so
/// the wire spelling of the key is pinned by a test rather than only by a live peer.
fn declare_proxy(params: &mut serde_json::Value, proxy: bool) {
    if let Some(object) = params.as_object_mut() {
        object.insert("proxy".to_string(), serde_json::Value::Bool(proxy));
    }
}

/// Read one framed JSON-RPC response body from `stream`, bounded by [`MAX_DESCRIPTOR_FRAME`].
async fn read_response_frame(
    stream: &mut dig_nat::PeerStream,
) -> std::io::Result<serde_json::Value> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_DESCRIPTOR_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "module descriptor frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// The per-attempt deadlines for one `dig.getModuleInfo`, in order — a LADDER, not a constant.
///
/// # Why a ladder and not a bigger number
///
/// Answering a descriptor is not a message round-trip: the holder reads the whole `.dig` and SHA-256s
/// every chunk (`module_serve`'s module docs). That cost scales with the capsule, and it is real —
/// a 135 MB capsule measured ~4.0 s on a host whose whole-file `cat` took 0.01 s, so a 1 GB capsule
/// is on the order of 30 s. There is no honest constant to pick, because **the asker cannot know the
/// size before the descriptor arrives**: `dig_dht::ProviderRecord` carries the holder's addresses and
/// expiry and no size at all, so a size-derived deadline has nothing to derive from on the first ask.
/// Any single number is therefore either too short for a large capsule or a blanket licence for a
/// slow peer to hold a slot on a small one.
///
/// A ladder needs no size. The total wait grows only for a holder that keeps being slow, and it is
/// bounded at the sum of the rungs; a fast holder still fails fast on the first rung.
///
/// # Why the later rungs are nearly free
///
/// A cold describe runs under `spawn_blocking` on the holder ([`crate::Node::describe_held_module`]),
/// and a blocking task is NOT cancelled when the requestor's stream drops — so the abandoned first ask
/// still runs to completion and populates that node's descriptor memo. The re-ask therefore lands on a
/// warm memo and is answered in milliseconds. Before this ladder the first ask was abandoned, the memo
/// warmed one millisecond too late, and nothing ever asked again (dig_ecosystem#3128).
///
/// # Why the retry lives HERE
///
/// dig-download's outer descriptor budget (`MAX_DESCRIPTOR_ATTEMPTS`) is spent only AFTER a descriptor
/// has been obtained and its pull failed; `fetch_module_info` returns through `?` on a transport
/// failure, so a merely-SLOW holder gets no budget at all (dig_ecosystem#3153). That is a dig-download
/// defect and is fixed there. This transport is the one layer in dig-node that can bound and re-ask a
/// single holder without it.
const DESCRIPTOR_ASK_DEADLINES: [std::time::Duration; 3] = [
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(15),
    std::time::Duration::from_secs(45),
];

/// The descriptor ask, as ONE indivisible unit: the deadline ladder, the second-pass relay
/// escalation, and the progress-bounded wait on a relaying hop.
///
/// # Why this is a MODULE and not three functions in the parent
///
/// Because a call site that can reach the middle of a decision will eventually be rewritten to do
/// exactly that. Measured on this very PR: an earlier revision unified the three steps into one
/// function, which made them inseparable from EACH OTHER but left the inner ladder helper reachable
/// from the parent -- and replacing the call site's body with a direct call to that helper deleted
/// BOTH the escalation and the relay wait from the shipped path with **968 tests still passing**.
///
/// The ladder lives in here and is PRIVATE, so the parent has no way to climb it except through
/// [`descriptor_for_holder`]. The parent supplies only a single one-shot ask, which carries no
/// policy at all. A bypass is therefore not merely untested, it does not compile -- and the one
/// remaining way to write it, re-implementing the ladder inline, is caught by
/// `the_production_get_module_info_climbs_the_whole_ladder` (which pins the elapsed ladder time
/// through the real method) together with
/// `a_cold_first_invocation_escalates_through_the_production_transport` (which pins the second round
/// through the real method's own locator).
///
/// Prefer making a defect unexpressible over asserting that it is absent.
mod descriptor_ask {
    use super::{ModuleInfo, DESCRIPTOR_ASK_DEADLINES};

    /// How a climb of the deadline ladder ended.
    ///
    /// The two failures are kept apart because they license different NEXT moves. A peer that answered
    /// has proved it can answer, so asking it a different question is worth a round trip; a peer that
    /// never answered has proved nothing except that it is unresponsive.
    #[derive(Debug, PartialEq, Eq)]
    enum LadderEnd<T> {
        /// The peer answered within a rung.
        Answered(T),
        /// The peer ANSWERED, and the answer was no.
        Refused,
        /// Every rung elapsed, or every attempt failed before it could answer.
        Exhausted,
    }

    /// Run `ask` under each of `deadlines` in turn, returning the first answer.
    ///
    /// Extracted from the dial so the LADDER's behaviour is testable on simulated time without a peer, a
    /// socket, or a capsule.
    async fn ask_within_deadlines<A, F, T>(
        deadlines: &[std::time::Duration],
        mut ask: A,
    ) -> LadderEnd<T>
    where
        A: FnMut() -> F,
        F: std::future::Future<Output = Option<T>>,
    {
        for (rung, deadline) in deadlines.iter().enumerate() {
            match tokio::time::timeout(*deadline, ask()).await {
                Ok(Some(answer)) => return LadderEnd::Answered(answer),
                // An attempt that ANSWERED "no" is a refusal, not slowness: re-asking cannot change it,
                // and spending the remaining rungs on it would make every genuine miss cost the full
                // ladder. Only an elapsed rung is retried.
                Ok(None) => return LadderEnd::Refused,
                Err(_elapsed) => tracing::debug!(
                    rung = rung + 1,
                    deadline_secs = deadline.as_secs(),
                    "module pull: descriptor ask exceeded its deadline; re-asking on the next rung"
                ),
            }
        }
        LadderEnd::Exhausted
    }

    /// Obtain the descriptor for one holder: ask at the pair's current phase, escalate to a RELAY ask
    /// within the same invocation if the plain round was answered with a no, and wait out a hop that
    /// answers that it is relaying.
    ///
    /// # Why all three steps live in ONE function
    ///
    /// They are one decision -- what this node does about a holder that did not simply hand over the
    /// descriptor -- and splitting them would leave a caller free to take the first step and skip the
    /// rest. That is not hypothetical: a helper extracted purely for testability is a helper a call
    /// site can quietly stop using, and its tests keep passing while the behaviour is gone.
    ///
    /// # Why the escalation happens here rather than on the next invocation (dig-node#322)
    ///
    /// The two-phase escalation itself is deliberate and stays: a requestor must not ask the whole
    /// connected pool to fetch a capsule on its behalf before establishing that no reachable holder
    /// exists, and that bound is what keeps the relay from being an amplification primitive. What was
    /// wrong was where the second phase happened. A cold requestor spent its FIRST invocation entirely on
    /// the plain round, so the documented single command could never relay and only an identical second
    /// command worked -- which a user reads as flakiness, with nothing in the output to say otherwise.
    /// Escalating here preserves the bound exactly (the plain round still goes first, and it is its
    /// emptiness that unlocks the second) while making one command sufficient.
    ///
    /// # Why only a REFUSAL escalates
    ///
    /// A peer that could not answer a plain ask within the whole ladder will not answer a relay ask
    /// either -- it travels the same stream to the same process. Escalating an exhausted ladder would
    /// double this method's wall clock in precisely the case where the extra time buys nothing, so
    /// [`LadderEnd::Exhausted`] ends the invocation and [`LadderEnd::Refused`] is what licenses phase two.
    pub(super) async fn descriptor_for_holder<A, F>(
        already_escalated: bool,
        relay_ceiling: std::time::Duration,
        mut ask_once: A,
    ) -> DescriptorOutcome
    where
        A: FnMut(bool) -> F,
        F: std::future::Future<Output = Option<DescriptorAnswer>>,
    {
        let mut answer =
            ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || ask_once(already_escalated)).await;
        if !already_escalated && matches!(answer, LadderEnd::Refused) {
            answer = ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || ask_once(true)).await;
        }
        match answer {
            LadderEnd::Answered(DescriptorAnswer::Descriptor(info)) => DescriptorOutcome {
                descriptor: Ok(*info),
                relay_waited: std::time::Duration::ZERO,
            },
            // The hop is FETCHING the capsule for us, so the ask is not over -- see
            // [`wait_for_relayed_descriptor`] for why the wait that follows is bounded by PROGRESS.
            LadderEnd::Answered(DescriptorAnswer::RelayPending { staged_bytes }) => {
                let started = tokio::time::Instant::now();
                let waited =
                    wait_for_relayed_descriptor(staged_bytes, relay_ceiling, ask_once).await;
                DescriptorOutcome {
                    descriptor: waited.map_err(DescriptorFailure::RelayWait),
                    relay_waited: started.elapsed(),
                }
            }
            LadderEnd::Refused | LadderEnd::Exhausted => DescriptorOutcome {
                descriptor: Err(DescriptorFailure::NoAnswer),
                relay_waited: std::time::Duration::ZERO,
            },
        }
    }

    /// What one holder's descriptor ask produced, and what it COST in relay waiting.
    ///
    /// The cost is reported rather than inferred because the caller charges it against a per-PULL budget
    /// (see `RelayWaitBudget`), and only this function can tell relay waiting apart from ladder time.
    pub(super) struct DescriptorOutcome {
        /// The descriptor, or this node's own name for why there is none.
        pub(super) descriptor: Result<ModuleInfo, DescriptorFailure>,
        /// How long was spent waiting on a RELAYING hop -- zero when no hop was relaying.
        pub(super) relay_waited: std::time::Duration,
    }

    /// Why a descriptor ask produced no descriptor. Named so the caller composes ONE transport error in
    /// this node's own vocabulary, and so the relay endings stay distinguishable in a log.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum DescriptorFailure {
        /// No holder answered, or the answer was no.
        NoAnswer,
        /// A hop was relaying and the wait on it ended without a descriptor.
        RelayWait(RelayWaitEnd),
    }

    impl DescriptorFailure {
        /// This node's own words for the failure. Never the peer's -- the crate sanitizes at its
        /// `Display` layer and upstream must not defeat it (#1603).
        pub(super) fn reason(self) -> &'static str {
            match self {
                DescriptorFailure::NoAnswer => "getModuleInfo failed",
                DescriptorFailure::RelayWait(end) => end.reason(),
            }
        }
    }

    /// What a descriptor ask came back with.
    ///
    /// The two are different FACTS, not two spellings of failure: a descriptor ends the ask, while a
    /// relay in progress says the hop is mid-way through answering it and the requestor may wait. Before
    /// dig-node#333 the second was indistinguishable from a miss, so a requestor abandoned a hop that was
    /// actively fetching on its behalf.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum DescriptorAnswer {
        /// The holder (or a hop that has finished relaying) described the capsule.
        ///
        /// Boxed because a [`ModuleInfo`] carries one hash and one length per chunk and is far larger
        /// than the other variant; an unboxed enum would pay that size on every ask.
        Descriptor(Box<ModuleInfo>),
        /// A hop is RELAYING the capsule for us and has staged this many bytes so far.
        RelayPending { staged_bytes: u64 },
    }

    /// How often a waiting requestor re-asks a relaying hop. Each poll is one small round trip, so this
    /// is chosen to keep the wait responsive without making a multi-minute relay expensive to observe.
    const RELAY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

    /// How long a relay may report NO forward progress before the requestor gives up on it.
    ///
    /// Sized well above [`RELAY_POLL_INTERVAL`] so ordinary jitter -- a poll that lands between two of
    /// the hop's staging writes -- never reads as a stall.
    const RELAY_STALL_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

    /// The hard ceiling on a single relay wait, however healthy the progress looks.
    ///
    /// **This is a security bound, not a tuning knob (NC-12).** The progress figure is a HOP'S CLAIM
    /// about itself, so a hostile hop can fabricate a counter that rises forever and a stall window alone
    /// would never catch it. The ceiling is what makes the worst case finite: a lying hop can waste this
    /// much of one pull's time from one peer, and no more. It is generous because an honest hop pulling a
    /// large capsule over a slow link is the case this whole path exists to serve, and the cost of that
    /// generosity is bounded -- the requestor is waiting on ONE peer, which it chose.
    pub(super) const RELAY_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

    /// Why a relay wait ended without producing a descriptor.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum RelayWaitEnd {
        /// The hop kept answering but stopped making progress.
        Stalled,
        /// The hop kept making progress for longer than any wait may last.
        Ceiling,
        /// The hop stopped answering, or answered something that is neither a descriptor nor progress.
        Abandoned,
    }

    impl RelayWaitEnd {
        /// This node's own vocabulary for the failure. Composed here rather than from anything the peer
        /// said, so a hop can never author what this node logs (#1603).
        pub(super) fn reason(self) -> &'static str {
            match self {
                RelayWaitEnd::Stalled => "the relaying hop stopped making progress",
                RelayWaitEnd::Ceiling => "the relay exceeded the maximum a single wait may last",
                RelayWaitEnd::Abandoned => "the relaying hop stopped answering",
            }
        }
    }

    /// Wait for a hop that is relaying a capsule for us, re-asking with `ask` until it produces the
    /// descriptor or one of [`RelayWaitEnd`]'s three endings.
    ///
    /// # Why the bound is PROGRESS and not a wall clock
    ///
    /// The descriptor ladder ([`DESCRIPTOR_ASK_DEADLINES`]) bounds a BLOCKING ask, where the cost of
    /// waiting is a held stream on both ends -- so a tight cap is exactly right for it, and dig-node#333
    /// is not a case of that cap being too small. The relay ask is no longer blocking: the hop ACKs and
    /// keeps pulling, so each further poll costs one small round trip. That changes which instrument is
    /// correct. A wall-clock cap on a transfer whose size the requestor cannot know before the descriptor
    /// arrives is either too short for a large capsule or a blanket licence for a slow one; forward
    /// PROGRESS needs no size, and a hop that is genuinely moving bytes is exactly the hop worth waiting
    /// for.
    ///
    /// Two bounds keep that honest, and both are required. [`RELAY_STALL_WINDOW`] ends a wait on a hop
    /// that has stopped moving. [`RELAY_MAX_WAIT`] ends it regardless, because the progress figure is the
    /// hop's own claim and a stall window cannot catch a liar who keeps counting (NC-12).
    ///
    /// **Progress never authorises a byte.** It decides only how long to keep waiting; the capsule that
    /// eventually arrives is verified against the chain-anchored root exactly as a direct holder's would
    /// be, and a hop that fabricated its way through this wait still cannot produce content that passes.
    async fn wait_for_relayed_descriptor<A, F>(
        staged_at_first_ask: u64,
        ceiling: std::time::Duration,
        mut ask_once: A,
    ) -> Result<ModuleInfo, RelayWaitEnd>
    where
        A: FnMut(bool) -> F,
        F: std::future::Future<Output = Option<DescriptorAnswer>>,
    {
        let started = tokio::time::Instant::now();
        let mut best = staged_at_first_ask;
        let mut last_advance = started;
        loop {
            // The ceiling is checked FIRST, before any further waiting, so a hop that keeps answering can
            // never buy one more poll past it.
            if started.elapsed() >= ceiling {
                return Err(RelayWaitEnd::Ceiling);
            }
            tokio::time::sleep(RELAY_POLL_INTERVAL).await;
            // Every poll is a full ladder climb, for the same reason the first ask was: a hop that
            // is mid-relay is doing real work and may answer slowly.
            match ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || ask_once(true)).await {
                LadderEnd::Answered(DescriptorAnswer::Descriptor(info)) => return Ok(*info),
                LadderEnd::Answered(DescriptorAnswer::RelayPending { staged_bytes }) => {
                    if staged_bytes > best {
                        best = staged_bytes;
                        last_advance = tokio::time::Instant::now();
                    } else if last_advance.elapsed() >= RELAY_STALL_WINDOW {
                        return Err(RelayWaitEnd::Stalled);
                    }
                    tracing::debug!(
                        staged_bytes,
                        "module pull: the hop is still relaying; waiting on its progress"
                    );
                }
                LadderEnd::Refused | LadderEnd::Exhausted => return Err(RelayWaitEnd::Abandoned),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The bound the FIELD behaved as if it had: three asks 2.00 s apart, the last abandoned one
        /// millisecond before the holder answered (the three-machine run behind dig_ecosystem#3128). The
        /// tests below use it as the BEFORE case, so "the new bound is better" is measured against what
        /// was actually observed rather than against a bound this file invented.
        const FIELD_DEADLINE: [std::time::Duration; 1] = [std::time::Duration::from_secs(2)];

        /// The measured cold-describe cost of the 135 MB capsule that failed: ~4.0 s on a host whose
        /// whole-file `cat` took 0.01 s, so it is compute, not disk.
        const COLD_135MB: std::time::Duration = std::time::Duration::from_millis(4_000);

        /// The same describe throughput (~34 MB/s) applied to a 1 GB capsule: ~30 s. Chosen FROM the
        /// measurement rather than picked, because the whole question the ladder answers is what happens
        /// when the capsule is larger than the one that was measured.
        const COLD_1GB: std::time::Duration = std::time::Duration::from_secs(30);

        /// A holder whose FIRST descriptor ask takes `cold` and whose later asks are answered from its
        /// memo in ~0 s — the real serve-side shape, because a cold describe runs under `spawn_blocking`
        /// on the holder ([`crate::Node::describe_held_module`]) and a blocking task is not cancelled when
        /// the requestor's stream drops, so an ABANDONED ask still warms the memo.
        ///
        /// It counts asks, so a test can distinguish "the ladder re-asked" from "the first ask was simply
        /// given longer".
        struct MemoizingHolder {
            warm_at: tokio::time::Instant,
            asks: std::cell::Cell<usize>,
        }

        impl MemoizingHolder {
            fn new(cold: std::time::Duration) -> Self {
                MemoizingHolder {
                    // The describe starts when the holder is first built, and finishes `cold` later
                    // whether or not anyone is still waiting — that is the non-cancellable property.
                    warm_at: tokio::time::Instant::now() + cold,
                    asks: std::cell::Cell::new(0),
                }
            }

            async fn ask(&self) -> Option<&'static str> {
                self.asks.set(self.asks.get() + 1);
                tokio::time::sleep_until(self.warm_at).await;
                Some("descriptor")
            }
        }

        /// **Proves:** the capsule that actually failed in the field is obtained under the new bound.
        ///
        /// **Catches:** the shipped behaviour — an ask abandoned before a legitimately-slow holder can
        /// answer, with nothing asking again.
        ///
        /// **Non-vacuous:** the companion below runs the SAME fixture under the bound the field behaved as
        /// if it had, and must fail. The fixture cannot pass by being fast — `COLD_135MB` is the measured
        /// cost and exceeds `FIELD_DEADLINE`.
        #[tokio::test(start_paused = true)]
        async fn the_capsule_that_failed_in_the_field_is_obtained_under_the_new_bound() {
            let holder = MemoizingHolder::new(COLD_135MB);

            let answer = ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || holder.ask()).await;

            assert_eq!(answer, LadderEnd::Answered("descriptor"));
        }

        /// **Proves:** the same 135 MB describe is LOST under the bound the field behaved as if it had —
        /// so the test above is load-bearing on the change, not on a generous fixture.
        #[tokio::test(start_paused = true)]
        async fn the_same_capsule_is_lost_under_the_field_deadline() {
            assert!(
                COLD_135MB > FIELD_DEADLINE[0],
                "the fixture must exceed the observed bound or it proves nothing"
            );
            let holder = MemoizingHolder::new(COLD_135MB);

            let answer = ask_within_deadlines(&FIELD_DEADLINE, || holder.ask()).await;

            assert_eq!(
                answer,
                LadderEnd::Exhausted,
                "the observed bound cannot outlast a 4.0 s describe"
            );
        }

        /// **Proves:** the LADDER, not merely a larger first rung, is what makes the bound scale — a
        /// capsule whose describe costs ~30 s is obtained, and it takes THREE asks to get it.
        ///
        /// **Catches:** collapsing `DESCRIPTOR_ASK_DEADLINES` back to one rung of any size. A single rung
        /// sized for 135 MB loses a 1 GB capsule (the companion below), and a single rung sized for 1 GB
        /// would let one unanswerable holder hold a descriptor slot for 30 s before the next is tried.
        ///
        /// **Non-vacuous:** the ask COUNT is asserted, so a fixture answered on rung 1 could not pass.
        #[tokio::test(start_paused = true)]
        async fn a_capsule_an_order_of_magnitude_larger_needs_the_later_rungs() {
            let holder = MemoizingHolder::new(COLD_1GB);

            let answer = ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || holder.ask()).await;

            assert_eq!(answer, LadderEnd::Answered("descriptor"));
            assert_eq!(
                holder.asks.get(),
                3,
                "rungs 1 and 2 must elapse and rung 3 must re-ask onto the warmed memo"
            );
        }

        /// **Proves:** a single rung sized for the measured capsule loses the order-of-magnitude-larger
        /// one — the reason the fix is a ladder rather than a bigger number.
        #[tokio::test(start_paused = true)]
        async fn one_rung_sized_for_the_measured_capsule_loses_the_larger_one() {
            let holder = MemoizingHolder::new(COLD_1GB);

            let answer =
                ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES[..1], || holder.ask()).await;

            assert_eq!(answer, LadderEnd::Exhausted);
        }

        /// **Proves:** a holder that ANSWERS "no" spends exactly one rung. A refusal is not slowness, and
        /// re-asking it would make every genuine miss cost the whole ladder before the next holder is
        /// tried.
        #[tokio::test(start_paused = true)]
        async fn a_refusal_does_not_climb_the_ladder() {
            let asks = std::cell::Cell::new(0usize);

            let answer: LadderEnd<&str> =
                ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || async {
                    asks.set(asks.get() + 1);
                    None
                })
                .await;

            // REFUSED, not exhausted: the two endings are kept apart because only the first licenses the
            // escalated re-ask dig-node#322 adds, and reading a silent peer as a refusal would double
            // every unanswerable holder's cost.
            assert_eq!(answer, LadderEnd::Refused);
            assert_eq!(asks.get(), 1, "a refused ask must not be retried");
        }

        /// **Proves:** the ladder is BOUNDED — an unanswerable holder costs the sum of the rungs and no
        /// more, so a slow or hostile peer cannot hold a descriptor slot indefinitely.
        #[tokio::test(start_paused = true)]
        async fn an_unanswerable_holder_costs_exactly_the_ladder() {
            let started = tokio::time::Instant::now();

            let answer: LadderEnd<&str> =
                ask_within_deadlines(&DESCRIPTOR_ASK_DEADLINES, || async {
                    std::future::pending::<()>().await;
                    None
                })
                .await;

            assert_eq!(answer, LadderEnd::Exhausted);
            assert_eq!(
                started.elapsed(),
                DESCRIPTOR_ASK_DEADLINES.iter().sum::<std::time::Duration>(),
                "the total wait must be exactly the ladder, never unbounded"
            );
        }

        // -- dig-node#333: waiting on a relaying hop -----------------------------------------------------

        /// The capsule the field run failed on: 134,968,945 bytes, measured on a three-machine
        /// `A -> B -> C` (dig_ecosystem#3128). Every relay fixture below is sized from it rather than
        /// from a round number, because the whole question is what happens to a REAL capsule.
        const FIELD_CAPSULE_BYTES: u64 = 134_968_945;

        /// A hop pulling [`FIELD_CAPSULE_BYTES`] at 1 MB/s -- an unremarkable rate for a residential
        /// uplink, and the one that makes the relay take the "minutes" the field observed.
        ///
        /// Chosen so the fixture DECISIVELY exceeds the descriptor ladder rather than merely brushing it:
        /// at ~135 s it is more than twice the ladder's 65 s total, so a test that passes cannot be
        /// explained by the ladder having been slightly generous.
        const FIELD_RELAY_BYTES_PER_POLL: u64 = 1_000_000 * 10;

        /// A hop that answers every ask with its staged progress, and finally with a descriptor once it
        /// has staged `completes_at` bytes.
        ///
        /// `advance_per_ask` is what varies between the tests below: a hop that is genuinely moving, one
        /// that has frozen, and one that fabricates motion it will never finish. Everything else is held
        /// constant, so a passing test cannot be explained by two differently-built fixtures.
        struct RelayingHop {
            staged: std::cell::Cell<u64>,
            advance_per_ask: u64,
            completes_at: Option<u64>,
            asks: std::cell::Cell<usize>,
        }

        impl RelayingHop {
            fn new(advance_per_ask: u64, completes_at: Option<u64>) -> Self {
                RelayingHop {
                    staged: std::cell::Cell::new(0),
                    advance_per_ask,
                    completes_at,
                    asks: std::cell::Cell::new(0),
                }
            }

            async fn ask(&self) -> Option<DescriptorAnswer> {
                self.asks.set(self.asks.get() + 1);
                self.staged.set(self.staged.get() + self.advance_per_ask);
                let staged = self.staged.get();
                match self.completes_at {
                    Some(target) if staged >= target => {
                        Some(DescriptorAnswer::Descriptor(Box::new(ModuleInfo {
                            total_size: FIELD_CAPSULE_BYTES,
                            module_hash: root(),
                            chunk_hashes: Vec::new(),
                            chunk_lens: Vec::new(),
                        })))
                    }
                    _ => Some(DescriptorAnswer::RelayPending {
                        staged_bytes: staged,
                    }),
                }
            }
        }

        /// **Proves (dig-node#333):** a requestor waits out a hop that is genuinely relaying, and gets the
        /// descriptor -- across a span the descriptor ladder could never have covered.
        ///
        /// **Catches:** the shipped behaviour exactly. The field run had the requestor abandon at 65 s
        /// while the hop went on to cache 134,968,945 bytes minutes later, so the capability was real and
        /// no first attempt could ever use it.
        ///
        /// **Non-vacuous:** the assertion is on ELAPSED VIRTUAL TIME as well as on the descriptor. A wait
        /// that merely returned the descriptor could be satisfied by a hop that answered immediately; the
        /// elapsed check requires the wait to have outlasted the whole ladder, which is the thing the old
        /// code structurally could not do.
        #[tokio::test(start_paused = true)]
        async fn a_requestor_waits_out_a_hop_that_is_genuinely_relaying() {
            let hop = RelayingHop::new(FIELD_RELAY_BYTES_PER_POLL, Some(FIELD_CAPSULE_BYTES));
            let ladder: std::time::Duration = DESCRIPTOR_ASK_DEADLINES.iter().sum();
            let started = tokio::time::Instant::now();

            // Driven through `descriptor_via_rounds` -- the function `get_module_info` itself calls --
            // rather than through the wait in isolation. A wait that is correct and no longer reached is
            // exactly the shape a revert-proof misses.
            let answer = descriptor_for_holder(true, RELAY_MAX_WAIT, |_proxy| hop.ask())
                .await
                .descriptor;

            assert!(
                answer.is_ok(),
                "a hop that is moving bytes must be waited for: {answer:?}"
            );
            assert!(
                started.elapsed() > ladder,
                "the fixture must outlast the {ladder:?} descriptor ladder or it proves nothing --              elapsed {:?}",
                started.elapsed()
            );
            assert!(
                started.elapsed() < RELAY_MAX_WAIT,
                "an honest relay must finish well inside the ceiling"
            );
        }

        /// **Proves:** a hop that has STOPPED making progress is abandoned after
        /// [`RELAY_STALL_WINDOW`], not waited on until the ceiling.
        ///
        /// **Why this is a separate test on a different hop behaviour:** the wait is a two-branch
        /// decision, and a suite proving only the keep-waiting branch is satisfied by a wait that never
        /// gives up at all. This hop answers every ask -- so it is not silent, and only the FROZEN counter
        /// distinguishes it -- and never advances.
        #[tokio::test(start_paused = true)]
        async fn a_frozen_relay_is_abandoned_after_the_stall_window() {
            let hop = RelayingHop::new(0, None);
            let started = tokio::time::Instant::now();

            let answer = descriptor_for_holder(true, RELAY_MAX_WAIT, |_proxy| hop.ask())
                .await
                .descriptor;

            assert_eq!(
                answer.unwrap_err(),
                DescriptorFailure::RelayWait(RelayWaitEnd::Stalled)
            );
            assert!(
                started.elapsed() < RELAY_STALL_WINDOW + RELAY_POLL_INTERVAL * 2,
                "a frozen hop must be dropped at the stall window, not held to the ceiling -- elapsed              {:?}",
                started.elapsed()
            );
        }

        /// **Proves (NC-12):** a hop that FABRICATES endless progress is bounded by [`RELAY_MAX_WAIT`].
        ///
        /// **Catches the nearest wrong implementation of this whole change:** a wait bounded only by
        /// forward progress. That version passes both tests above and hangs forever here, because the
        /// staged byte count is the hop's claim about itself and a liar who keeps counting never stalls.
        ///
        /// **Why the fixture cannot pass by accident:** this hop advances by ONE byte per ask and never
        /// completes, so it is indistinguishable from an honest, very slow relay by progress alone. Only
        /// the ceiling can end it.
        #[tokio::test(start_paused = true)]
        async fn a_hop_that_fabricates_endless_progress_is_bounded_by_the_ceiling() {
            let hop = RelayingHop::new(1, None);
            let started = tokio::time::Instant::now();

            // Bounded at twice the ceiling so a REGRESSION FAILS rather than hangs. Without it the
            // absent-ceiling case loops forever burning CPU on virtual time, which reads in CI as a stuck
            // job rather than a failed assertion -- and a test that hangs on regression is a landmine for
            // whoever trips it. Measured: this test's own revert-proof spun for 659 CPU-seconds before it
            // was killed.
            let answer = tokio::time::timeout(
                RELAY_MAX_WAIT * 2,
                descriptor_for_holder(true, RELAY_MAX_WAIT, |_proxy| hop.ask()),
            )
            .await
            .expect(
                "the wait MUST end at the ceiling; an unbounded wait is the NC-12 defect itself",
            )
            .descriptor;

            assert_eq!(
                answer.unwrap_err(),
                DescriptorFailure::RelayWait(RelayWaitEnd::Ceiling)
            );
            assert!(
                started.elapsed() >= RELAY_MAX_WAIT,
                "the wait must run to the ceiling before ending"
            );
            assert!(
                started.elapsed() < RELAY_MAX_WAIT + RELAY_POLL_INTERVAL * 2,
                "and must end AT the ceiling, not merely somewhere after it -- elapsed {:?}",
                started.elapsed()
            );
        }

        /// **Proves (finding 2):** the ceiling handed in is the ceiling USED — a hop gets only what the
        /// pull has left, never a fresh [`RELAY_MAX_WAIT`].
        ///
        /// **Catches the shape of a half-applied budget:** a parameter that is accepted, threaded, and
        /// then ignored in favour of the constant. That version passes every other test in this module,
        /// because every other test hands in exactly `RELAY_MAX_WAIT`.
        ///
        /// **Fixture design:** the hop is the SAME endless-progress liar as the ceiling test above, so the
        /// only thing that varies is the budget it is granted. Its ending is identical; only the elapsed
        /// time distinguishes the two, which is precisely the property under test.
        #[tokio::test(start_paused = true)]
        async fn a_hop_gets_only_what_the_pull_has_left() {
            let hop = RelayingHop::new(1, None);
            let nearly_spent = RELAY_POLL_INTERVAL * 3;
            let started = tokio::time::Instant::now();

            let answer = descriptor_for_holder(true, nearly_spent, |_proxy| hop.ask()).await;

            assert_eq!(
                answer.descriptor.unwrap_err(),
                DescriptorFailure::RelayWait(RelayWaitEnd::Ceiling)
            );
            assert!(
            started.elapsed() < nearly_spent + RELAY_POLL_INTERVAL * 2,
            "the wait must end at the budget it was GIVEN, not at the per-hop maximum -- elapsed              {:?} against a budget of {nearly_spent:?}",
            started.elapsed()
        );
            assert!(
                started.elapsed() < RELAY_MAX_WAIT,
                "the control: a ceiling that was ignored would run to {RELAY_MAX_WAIT:?}"
            );
        }

        /// **Proves:** the relay wait is REPORTED, so a caller can charge it — and reported as zero when
        /// no hop relayed, so an ordinary ask never consumes a pull's budget.
        ///
        /// **Why both halves:** a report that is always zero would silently disable the budget, and a
        /// report that is never zero would exhaust it on ordinary asks. Neither is visible from the
        /// outcome alone.
        #[tokio::test(start_paused = true)]
        async fn only_a_relaying_hop_costs_the_pull_any_relay_time() {
            let relaying = RelayingHop::new(FIELD_RELAY_BYTES_PER_POLL, Some(FIELD_CAPSULE_BYTES));
            let waited = descriptor_for_holder(true, RELAY_MAX_WAIT, |_proxy| relaying.ask())
                .await
                .relay_waited;
            assert!(
                waited > std::time::Duration::ZERO,
                "a hop that relayed must report the time it cost"
            );

            let holder = RelayingHop::new(u64::MAX, Some(1));
            let none = descriptor_for_holder(true, RELAY_MAX_WAIT, |_proxy| holder.ask())
                .await
                .relay_waited;
            assert_eq!(
                none,
                std::time::Duration::ZERO,
                "a holder that simply answered must cost the pull no relay budget at all"
            );
        }

        /// **Proves:** a hop that stops answering ends the wait immediately, rather than being polled to
        /// the ceiling. A relay that died is not a relay in progress.
        #[tokio::test(start_paused = true)]
        async fn a_hop_that_stops_answering_ends_the_wait() {
            // First round: relaying. Every round after: silence. Only the SECOND round can produce the
            // abandonment, so a fixture that was silent from the start could not exhibit it.
            let rounds = std::cell::Cell::new(0usize);
            let answer = descriptor_for_holder(true, RELAY_MAX_WAIT, |_proxy| {
                let ix = rounds.get();
                rounds.set(ix + 1);
                async move {
                    if ix == 0 {
                        Some(DescriptorAnswer::RelayPending { staged_bytes: 1 })
                    } else {
                        None
                    }
                }
            })
            .await
            .descriptor;

            assert_eq!(
                answer.unwrap_err(),
                DescriptorFailure::RelayWait(RelayWaitEnd::Abandoned)
            );
        }

        // -- dig-node#322: escalating within one invocation -----------------------------------------------

        /// Record the `proxy` phase of every round an escalation drives, so the SEQUENCE is the assertion
        /// rather than a count that a single escalated round would also satisfy.
        /// How a fixture holder ends a ROUND, expressed at the one-shot level the production closure
        /// actually supplies.
        #[derive(Clone, Copy)]
        enum RoundEnding {
            /// Answers, and the answer is no. One rung is spent and the ladder stops.
            Refuses,
            /// Never answers at all, so every rung of the ladder elapses.
            Silent,
        }

        /// The sequence of ROUNDS a descriptor ask drives, by phase, with each round ending as named.
        ///
        /// The ending is chosen BY PHASE rather than by call index, because a round is not one ask -- a
        /// silent holder is asked once per rung, so an index-keyed fixture serves round two's ending to
        /// round one's second rung and manufactures an escalation that never happened. That mistake made
        /// this exact test report `[false, false, true]`; keying on the phase is what makes the fixture
        /// describe rounds instead of asks.
        ///
        /// Consecutive asks at the same phase collapse into the one round they belong to, so the result
        /// is the round sequence and never a rung count.
        async fn phases_of(
            already_escalated: bool,
            plain: RoundEnding,
            escalated: RoundEnding,
        ) -> Vec<bool> {
            let seen = std::cell::RefCell::new(Vec::new());
            let _ = descriptor_for_holder(already_escalated, RELAY_MAX_WAIT, |proxy| {
                seen.borrow_mut().push(proxy);
                let ending = if proxy { escalated } else { plain };
                async move {
                    match ending {
                        RoundEnding::Refuses => None,
                        // Pending forever: under `start_paused` the runtime advances the virtual clock,
                        // so every rung elapses and the ladder ends Exhausted -- the real shape of an
                        // unresponsive peer, rather than a value standing in for one.
                        RoundEnding::Silent => std::future::pending().await,
                    }
                }
            })
            .await;
            let mut rounds: Vec<bool> = Vec::new();
            for phase in seen.into_inner() {
                if rounds.last() != Some(&phase) {
                    rounds.push(phase);
                }
            }
            rounds
        }

        /// **Proves (dig-node#322):** a cold requestor's FIRST invocation escalates, once its plain round
        /// has been answered with a no -- so the documented single command can relay.
        ///
        /// **The assertion is the PHASE SEQUENCE, not a round count.** A count of two is satisfied by two
        /// plain rounds, and a count of one by an implementation that escalated immediately -- which would
        /// remove the amplification bound this change must preserve. `[false, true]` is the only sequence
        /// that is both fixed and correct.
        #[tokio::test(start_paused = true)]
        async fn a_cold_first_invocation_spends_a_plain_round_then_escalates() {
            let phases = phases_of(false, RoundEnding::Refuses, RoundEnding::Refuses).await;

            assert_eq!(
                phases,
                vec![false, true],
                "the plain round must come FIRST and the relay ask must follow it in the same invocation"
            );
        }

        /// **Proves:** an EXHAUSTED plain round is not escalated, so an unresponsive holder still costs
        /// exactly one ladder.
        ///
        /// **Catches the obvious over-broad version of the #322 fix** -- escalate whenever the round
        /// produced no descriptor -- which doubles `get_module_info`'s wall clock on every silent peer.
        /// Its production-path companion is
        /// [`the_production_get_module_info_climbs_the_whole_ladder`], which pins the same fact in
        /// virtual seconds through the real method.
        #[tokio::test(start_paused = true)]
        async fn an_unresponsive_holder_is_not_escalated() {
            let phases = phases_of(false, RoundEnding::Silent, RoundEnding::Refuses).await;

            assert_eq!(
                phases,
                vec![false],
                "a peer that could not answer a plain ask must not be asked to relay as well"
            );
        }

        /// **Proves:** a pair that has ALREADY spent its plain round asks once, escalated. The escalation
        /// is a second pass per `(capsule, peer)` pair, never a second pass per invocation.
        #[tokio::test(start_paused = true)]
        async fn an_already_escalated_pair_asks_once() {
            let phases = phases_of(true, RoundEnding::Refuses, RoundEnding::Refuses).await;

            assert_eq!(phases, vec![true]);
        }

        /// A canonical 64-hex id, so a fixture descriptor's `module_hash` is the right shape.
        fn root() -> String {
            [0xCDu8; 32].iter().map(|b| format!("{b:02x}")).collect()
        }
    }
}

/// One `dig.getModuleInfo` over `peer`, decoded into a [`ModuleInfo`]. `proxy` declares whether this
/// ask permits the far end to fetch the capsule on this node's behalf.
///
/// `None` for every failure — a refused stream, an unwritable request, an unreadable frame, an error
/// envelope, or a body that is not a descriptor. The caller turns that into one transport error whose
/// text is this node's own, so a peer can never author what this node logs (#1603).
async fn descriptor_over(
    peer: &mut DigPeer,
    store_id: &str,
    root: &str,
    proxy: bool,
) -> Option<DescriptorAnswer> {
    let params = serde_json::to_value(GetModuleInfoParams {
        store_id: store_id.to_string(),
        root: root.to_string(),
    })
    .ok()?;
    let mut stream = peer.open_stream().await.ok()?;
    ask_with_proxy(
        &mut stream,
        dig_rpc_protocol::Method::GetModuleInfo,
        params,
        proxy,
    )
    .await
    .ok()?;
    let response = read_response_frame(&mut stream).await.ok()?;
    if let Some(result) = response.get("result") {
        return serde_json::from_value(result.clone())
            .ok()
            .map(|info: ModuleInfo| DescriptorAnswer::Descriptor(Box::new(info)));
    }
    relay_progress_in(&response).map(|staged_bytes| DescriptorAnswer::RelayPending { staged_bytes })
}

/// The staged byte count a RELAY-IN-PROGRESS answer carries, or `None` for any other answer.
///
/// Keyed on the `data` FIELD rather than on the error code alone, and deliberately so: the code is
/// the taxonomy's ordinary inconclusive miss, which an honest non-relaying node also returns when its
/// own lookup was unsettled. Only a node that is relaying reports the field, so only the field
/// distinguishes "wait for me" from "I could not find out".
fn relay_progress_in(response: &serde_json::Value) -> Option<u64> {
    let error = response.get("error")?;
    if error.get("code")?.as_i64()? != crate::download::content_miss_inconclusive() {
        return None;
    }
    error
        .get("data")?
        .get(crate::RELAY_PROGRESS_FIELD)?
        .as_u64()
}

/// Open a `dig.fetchModuleRange` frame stream over `peer`, at the phase `proxy` names.
///
/// The phase is the CALLER's to decide and is not re-derived here: a window sent through a hop must
/// carry the relay opt-in that hop expects, or it refuses at gate (1) and the pull stalls one frame
/// after it was admitted. See [`RelayEscalation::escalate_for`] for how the caller picks it.
async fn window_stream_over(
    peer: &mut DigPeer,
    store_id: &str,
    root: &str,
    offset: u64,
    length: u64,
    proxy: bool,
) -> Option<dig_nat::PeerStream> {
    let params = serde_json::to_value(FetchModuleRangeParams {
        store_id: store_id.to_string(),
        root: root.to_string(),
        offset: Some(offset),
        length,
    })
    .ok()?;
    let mut stream = peer.open_stream().await.ok()?;
    ask_with_proxy(
        &mut stream,
        dig_rpc_protocol::Method::FetchModuleRange,
        params,
        proxy,
    )
    .await
    .ok()?;
    Some(stream)
}

impl NatModuleTransport {
    /// ONE descriptor ask of `provider_peer_id` at the phase `proxy` names -- a dial, a question, a
    /// hang-up, and nothing else.
    ///
    /// This carries NO policy: no ladder, no escalation, no waiting. Every one of those lives in
    /// [`descriptor_ask`], which drives this. Keeping the primitive policy-free is what makes the
    /// policy unbypassable — there is nothing here a call site could use to get a descriptor
    /// "almost" the right way.
    ///
    /// Each round re-dials: an abandoned round's connection is gone, and the holder's descriptor memo
    /// -- not the connection -- is what makes the re-ask cheap. See [`DESCRIPTOR_ASK_DEADLINES`].
    async fn ask_descriptor_once(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
        proxy: bool,
    ) -> Option<descriptor_ask::DescriptorAnswer> {
        let mut peer = self.connect(provider_peer_id, store_id, root).await.ok()?;
        let answer = descriptor_over(&mut peer, store_id, root, proxy).await;
        peer.disconnect().await;
        answer
    }
}

#[async_trait]
impl ModuleTransport for NatModuleTransport {
    async fn get_module_info(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
    ) -> Result<ModuleInfo, DownloadError> {
        // The pair's phase, decided ONCE per invocation rather than re-read inside the ladder, so the
        // rounds below say plainly which is which. `escalate_for` records the pair, so this is `false`
        // exactly on the pair's first invocation.
        let already_escalated = self
            .escalation
            .escalate_for(store_id, root, provider_peer_id);

        // The ceiling handed down is what is LEFT of this PULL's relay-wait budget, not a fresh
        // per-peer allowance. See [`RelayWaitBudget`] for why the difference is the whole point.
        let outcome = descriptor_ask::descriptor_for_holder(
            already_escalated,
            self.relay_budget.remaining(store_id, root),
            |proxy| self.ask_descriptor_once(provider_peer_id, store_id, root, proxy),
        )
        .await;
        self.relay_budget
            .charge(store_id, root, outcome.relay_waited);

        // The reason names the STEP and the sentinelled peer; the peer's own answer text is never
        // embedded (#1603).
        outcome
            .descriptor
            .map_err(|failure| DownloadError::transport(provider_peer_id, failure.reason()))
    }

    async fn fetch_module_range(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, DownloadError> {
        let mut peer = self.connect(provider_peer_id, store_id, root).await?;
        // Escalation LATCHES per `(capsule, peer)` pair rather than per request: `escalate_for`
        // records on its first read, so the pair's FIRST ask — its descriptor — goes plain and every
        // later ask for that pair, windows included, is escalated. That is the bound WU2 wants: one
        // plain round is spent per pair before any relay is asked of it, and a pair whose plain round
        // produced no holder does not spend a second one. A window therefore does NOT necessarily
        // ride at its own descriptor's phase, and must not be documented as if it did.
        let proxy = self
            .escalation
            .escalate_for(store_id, root, provider_peer_id);
        let bytes = match window_stream_over(&mut peer, store_id, root, offset, length, proxy).await
        {
            Some(mut stream) => read_module_window(&mut stream, provider_peer_id, length).await,
            None => Err(DownloadError::transport(
                provider_peer_id,
                "fetchModuleRange stream refused",
            )),
        };
        peer.disconnect().await;
        bytes
    }
}

/// Reassemble one requested window from the holder's `RangeFrame` stream.
///
/// A holder legitimately answers at its OWN frame granularity, so this reads until a frame reports
/// `complete` rather than trusting the first frame — and stops the moment `length` bytes have arrived,
/// so a holder cannot make the puller buffer more than it asked for by never setting `complete`.
async fn read_module_window(
    stream: &mut dig_nat::PeerStream,
    peer_hex: &str,
    length: u64,
) -> Result<Vec<u8>, DownloadError> {
    let mut assembled: Vec<u8> = Vec::new();
    loop {
        let frame = dig_nat::RangeFrame::decode(stream)
            .await
            .map_err(|_| DownloadError::transport(peer_hex, "malformed module range frame"))?
            .ok_or_else(|| {
                DownloadError::transport(peer_hex, "module range stream ended before completion")
            })?;
        assembled.extend_from_slice(&frame.bytes);
        // The `length` bound is what makes a never-`complete` holder harmless: an unbounded read here
        // would let one peer grow this buffer without limit for the cost of one request.
        if frame.complete || assembled.len() as u64 >= length {
            break;
        }
    }
    // Return whatever arrived. The engine clips an overshoot and rejects a short range against
    // `chunk_hashes` — attribution is ITS job, and duplicating the judgement here would let the two
    // disagree.
    Ok(assembled)
}

/// The capsule-granularity [`ContentId`] naming a `(store_id, root)` module, or `None` if either id is
/// not canonical 64-hex.
fn module_content_id(store_id: &str, root: &str) -> Option<ContentId> {
    Some(ContentId::capsule(decode_id(store_id)?, decode_id(root)?))
}

/// The DHT key of the capsule a module pull names, for building the `ProviderRecord` that
/// [`dial_candidates`] orders.
fn module_content_key(store_id: &str, root: &str) -> Result<dig_dht::Key, DownloadError> {
    module_content_id(store_id, root)
        .map(|c| c.to_key())
        .ok_or(DownloadError::NotDownloadable)
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

/// A peer_id → addresses map in the shape [`ConnectedPool`] holds, for the wiring tests.
#[cfg(test)]
pub(crate) fn pool_of(entries: &[(&str, &str)]) -> ConnectedPool {
    let mut map = std::collections::HashMap::new();
    for (peer, addr) in entries {
        map.insert(
            (*peer).to_string(),
            vec![addr.parse::<std::net::SocketAddr>().expect("test addr")],
        );
    }
    Arc::new(std::sync::Mutex::new(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical 64-hex id built from a repeated byte, so a test id can never be the wrong length.
    fn id_of(byte: u8) -> String {
        [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
    }

    fn store() -> String {
        id_of(0xaa)
    }

    fn root() -> String {
        id_of(0xbb)
    }

    fn peer_hex(n: u8) -> String {
        PeerId::from_bytes([n; 32]).to_hex()
    }

    /// A locator that offers `addrs` for the given peer at capsule granularity.
    struct StubLocator {
        peer: String,
        addrs: Vec<CandidateAddr>,
    }

    #[async_trait]
    impl ProviderLocator for StubLocator {
        async fn find_providers(
            &self,
            content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            let peer = PeerId::from_hex(&self.peer).expect("test peer id");
            Ok(vec![ProviderRecord::new(
                &content.to_key(),
                &peer,
                self.addrs.clone(),
                u64::MAX,
            )])
        }
    }

    fn transport(
        connected: ConnectedPool,
        locator: Arc<dyn ProviderLocator>,
    ) -> NatModuleTransport {
        let key = dig_tls::bls::SecretKey::from_seed(&[7u8; 32]);
        NatModuleTransport::new(
            Arc::new(dig_nat::NodeCert::generate_signed(&key).expect("cert")),
            dig_nat::NatConfig::default(),
            "DIG_TESTNET",
            Arc::new(dig_nat::NatRuntime::default()),
            connected,
            locator,
        )
    }

    /// A locator that never answers, so a `get_module_info` hangs inside its own dial preparation.
    ///
    /// The hang is placed in a SEAM this test owns rather than in the network: a real dial to a
    /// black-holed address is a race (a routable-but-closed port answers `ECONNREFUSED` in
    /// milliseconds, which is a REFUSAL and correctly spends one rung), and a test whose meaning
    /// depends on which error a CI host's network stack happens to produce is not a test of this
    /// call site.
    struct HangingLocator;

    #[async_trait]
    impl ProviderLocator for HangingLocator {
        async fn find_providers(
            &self,
            _content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            std::future::pending().await
        }
    }

    /// **Proves:** the PRODUCTION entry point — `ModuleTransport::get_module_info`, the method
    /// dig-download actually calls — climbs the whole ladder. An unanswerable holder costs exactly
    /// the sum of [`DESCRIPTOR_ASK_DEADLINES`], which no single-deadline call site can produce.
    ///
    /// **Catches:** the call site being rewired to one fixed deadline while `ask_within_deadlines`
    /// stays perfectly correct and perfectly unused. That is the same class as the defect this whole
    /// change fixes, and this repo has already paid for it once: `download.rs:1397-1401` records a
    /// warm whose every test built its own mock locator, none of which sat on production's path.
    ///
    /// **Non-vacuous:** the assertion is on ELAPSED VIRTUAL TIME through the real method, so it
    /// cannot be satisfied by the helper being correct in isolation. A bypassed ladder yields one
    /// deadline; a missing ladder yields ~zero.
    ///
    /// **Why it terminates:** under `start_paused` the runtime advances the clock whenever no task is
    /// runnable, so the pending locator never blocks the wall clock — only the virtual one.
    #[tokio::test(start_paused = true)]
    async fn the_production_get_module_info_climbs_the_whole_ladder() {
        let peer = peer_hex(1);
        let t = transport(pool_of(&[]), Arc::new(HangingLocator));
        let started = tokio::time::Instant::now();

        // Bounded at twice the ladder so a REGRESSION FAILS rather than hangs. A call site that
        // stops going through [`descriptor_ask`] has no ladder at all, so it waits on the pending
        // locator forever -- measured, when the gate's bypass was reproduced here. A test that hangs
        // on regression reads in CI as a stuck job rather than a failed assertion.
        let ladder: std::time::Duration = DESCRIPTOR_ASK_DEADLINES.iter().sum();
        let result = tokio::time::timeout(ladder * 2, t.get_module_info(&peer, &store(), &root()))
            .await
            .expect(
                "`get_module_info` must be BOUNDED by the ladder; an unbounded ask is the defect",
            );

        assert!(
            result.is_err(),
            "an unanswerable holder yields no descriptor"
        );
        assert_eq!(
            started.elapsed(),
            DESCRIPTOR_ASK_DEADLINES.iter().sum::<std::time::Duration>(),
            "`get_module_info` must spend every rung of the ladder, not one fixed deadline"
        );
    }

    /// Counts how many times the production path asked discovery for this capsule's providers.
    ///
    /// The count is the ROUND count seen from outside: every descriptor round dials, every dial
    /// resolves candidates, and every resolution consults the locator exactly once. So a locator that
    /// counts is an observer of the production method's round structure that needs no peer, no
    /// socket and no injected seam.
    #[derive(Default)]
    struct CountingLocator {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ProviderLocator for CountingLocator {
        async fn find_providers(
            &self,
            _content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // No providers and no error: an ANSWER of "nobody", so the round is refused rather than
            // exhausted -- which is exactly the condition dig-node#322 says must escalate.
            Ok(Vec::new())
        }
    }

    /// **Proves (dig-node#322, at the PRODUCTION entry point):** one call to the real
    /// `ModuleTransport::get_module_info` drives TWO descriptor rounds when the first is refused —
    /// the plain round and the escalated one — so the documented single command can relay.
    ///
    /// **Catches what the unit-level escalation tests structurally cannot:** a call site that stops
    /// driving [`descriptor_ask`] at all. The gate proved that was possible — replacing this method's
    /// body with a direct one-shot ask deleted both the escalation and the relay wait from the
    /// shipped path with every test still green, because every test drove the helper rather than the
    /// method. This one drives the method.
    ///
    /// **Non-vacuous:** the assertion is TWO, not "at least one". A bypass that keeps a single round
    /// yields one; a fixture that never reached the transport at all yields zero. Only the escalation
    /// produces two, and the companion above pins that the rounds are a plain one then a relay one.
    #[tokio::test(start_paused = true)]
    async fn a_cold_first_invocation_escalates_through_the_production_transport() {
        let peer = peer_hex(1);
        let locator = Arc::new(CountingLocator::default());
        let t = transport(
            pool_of(&[]),
            Arc::clone(&locator) as Arc<dyn ProviderLocator>,
        );

        let result = t.get_module_info(&peer, &store(), &root()).await;

        assert!(
            result.is_err(),
            "no holder answered, so there is no descriptor"
        );
        assert_eq!(
            locator.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a refused plain round must be followed by an ESCALATED round inside the same call;              one round means the call site is no longer driving the escalation"
        );
    }

    /// **Proves (finding 2):** the relay-wait budget is spent per CAPSULE, drains, and saturates —
    /// so many hops on one pull share one allowance while a different pull is untouched.
    ///
    /// **Catches:** a budget keyed by peer, or one that resets, either of which restores the
    /// `holders × ceiling` multiplication the budget exists to remove.
    #[test]
    fn the_relay_budget_is_spent_per_capsule_and_saturates() {
        let budget = RelayWaitBudget::default();
        let (store, root) = (store(), root());
        let full = RELAY_WAIT_BUDGET_PER_PULL;

        assert_eq!(
            budget.remaining(&store, &root),
            full,
            "a fresh pull has all of it"
        );

        // Two different HOPS of the same pull, charged separately, draw down the same allowance.
        budget.charge(&store, &root, full / 4);
        budget.charge(&store, &root, full / 4);
        assert_eq!(
            budget.remaining(&store, &root),
            full / 2,
            "hops of one pull SHARE the budget; a per-peer allowance would still read as full here"
        );

        // A different capsule is a different pull.
        assert_eq!(
            budget.remaining(&store, &id_of(0x77)),
            full,
            "the control: another capsule must be unaffected, or the ledger is global rather than              per pull"
        );

        // Overrun saturates instead of wrapping into a fresh allowance.
        budget.charge(&store, &root, full);
        assert_eq!(
            budget.remaining(&store, &root),
            std::time::Duration::ZERO,
            "an overrun must leave nothing, never wrap"
        );
    }

    /// **Proves:** an IPv6 candidate becomes a dialable target with its address BRACKETED — the exact
    /// bug that blocked the entire read leg, where `format!("{host}:{port}")` + `parse::<SocketAddr>()`
    /// failed with "invalid socket address syntax" before a socket was ever opened (#1593).
    /// **Catches:** any reintroduction of string-concatenated address construction on this leg.
    #[tokio::test]
    async fn an_ipv6_candidate_is_dialable_and_bracketed() {
        let peer = peer_hex(1);
        let t = transport(
            pool_of(&[(&peer, "[::ffff:172.31.79.22]:9444")]),
            Arc::new(StubLocator {
                peer: peer.clone(),
                addrs: vec![],
            }),
        );

        let targets = t
            .dial_targets(&peer, &store(), &root())
            .await
            .expect("targets");
        let addrs: Vec<&str> = targets.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            addrs
                .iter()
                .any(|a| a.starts_with('[') && a.contains("]:9444")),
            "the v6 candidate must be bracketed, got {addrs:?}"
        );
    }

    /// **Proves:** IPv6 candidates are dialed BEFORE IPv4 ones (§5.2 IPv6-first, IPv4-fallback), and a
    /// relay-only target is always available last so a holder with no working address is still
    /// reachable by identity.
    #[tokio::test]
    async fn ipv6_is_dialed_before_ipv4_and_relay_only_is_last() {
        let peer = peer_hex(2);
        let t = transport(
            pool_of(&[(&peer, "10.0.0.5:9444")]),
            Arc::new(StubLocator {
                peer: peer.clone(),
                addrs: vec![CandidateAddr::direct("2001:db8::1".to_string(), 9444)],
            }),
        );

        let targets = t
            .dial_targets(&peer, &store(), &root())
            .await
            .expect("targets");
        let addrs: Vec<String> = targets.iter().map(|(a, _)| a.clone()).collect();
        let v6 = addrs.iter().position(|a| a.contains("2001:db8"));
        let v4 = addrs.iter().position(|a| a.contains("10.0.0.5"));
        assert!(
            v6 < v4,
            "IPv6 must lead the dial order (§5.2), got {addrs:?}"
        );
        assert_eq!(
            addrs.last().map(String::as_str),
            Some("relay-only"),
            "relay-only reachability is the final fallback, got {addrs:?}"
        );
    }

    /// **Proves:** a malformed `provider_peer_id` is refused before any dial is attempted, rather than
    /// producing a connect attempt against a peer identity that cannot exist.
    #[tokio::test]
    async fn a_malformed_peer_id_is_refused_before_dialing() {
        let t = transport(
            pool_of(&[]),
            Arc::new(StubLocator {
                peer: peer_hex(3),
                addrs: vec![],
            }),
        );
        let err = t
            .dial_targets("not-a-peer-id", &store(), &root())
            .await
            .expect_err("refused");
        assert!(matches!(err, DownloadError::Transport { .. }), "got {err}");
    }

    /// **Proves:** a DHT locate failure never removes the LIVE pool address — discovery is best-effort,
    /// and losing a connection-verified address to a transient DHT error is exactly how a reachable
    /// holder becomes unreachable (#836).
    #[tokio::test]
    async fn a_failing_locator_does_not_lose_the_live_pool_address() {
        struct FailingLocator;
        #[async_trait]
        impl ProviderLocator for FailingLocator {
            async fn find_providers(
                &self,
                _content: &ContentId,
            ) -> Result<Vec<ProviderRecord>, DownloadError> {
                Err(DownloadError::NotDownloadable)
            }
        }

        let peer = peer_hex(4);
        let t = transport(
            pool_of(&[(&peer, "10.0.0.9:9444")]),
            Arc::new(FailingLocator),
        );
        let targets = t
            .dial_targets(&peer, &store(), &root())
            .await
            .expect("targets");
        assert!(
            targets.iter().any(|(a, _)| a == "10.0.0.9:9444"),
            "the pool address survived a locator failure"
        );
    }

    /// **Proves:** the FIRST module request to a `(capsule, peer)` pair is plain, and only a SECOND
    /// pass over the same pair escalates to the relay opt-in.
    ///
    /// **Catches:** the shipped `proxy: true` on every request. That was inert while the module
    /// pull's provider set was holders-only, and stops being inert the moment the warm locator
    /// unions the connected pool: A's first descriptor probe to every connected peer would become a
    /// request to fetch a whole capsule on A's behalf, before A had established that no reachable
    /// holder exists.
    ///
    /// **Fixture design — three actors, because the nearest wrong implementations differ only in
    /// what they key on.** A single ask/re-ask pair is satisfied by a ledger keyed on the peer alone
    /// (which would relay a DIFFERENT capsule to a peer already asked about another) and equally by
    /// one keyed on the capsule alone (which would relay to a peer never asked at all). Both are
    /// plausible, both widen exactly what this bounds, and only a second capsule and a second peer
    /// can see either.
    #[test]
    fn the_relay_opt_in_is_a_second_pass_escalation_per_capsule_and_peer() {
        let escalation = RelayEscalation::default();
        let (store, root, peer) = (store(), root(), peer_hex(1));

        assert!(
            !escalation.escalate_for(&store, &root, &peer),
            "the FIRST descriptor round must be plain: nothing yet establishes that no reachable \
             holder exists, so asking this peer to relay recruits a courier before looking"
        );
        assert!(
            escalation.escalate_for(&store, &root, &peer),
            "a SECOND pass over a pair a plain round did not answer is exactly when the relay is \
             worth asking for - without this the escalation never happens and the leg is dead"
        );

        assert!(
            !escalation.escalate_for(&store, &id_of(0xcc), &peer),
            "CONTROL: a DIFFERENT capsule to the same peer is a new question, so it starts plain. \
             A ledger keyed on the peer alone would relay it."
        );
        assert!(
            !escalation.escalate_for(&store, &root, &peer_hex(2)),
            "CONTROL: the same capsule to a peer never asked is a new question too. A ledger keyed \
             on the capsule alone would relay it - to a peer that may well be the holder."
        );
    }

    /// **Proves:** the decision reaches the WIRE under the key the far end reads, in both states.
    ///
    /// **Catches:** an escalation that is computed correctly and then dropped, or written as a
    /// present-vs-absent key. `relay_capsule`'s gate (1) reads `proxy` as a boolean; omitting it on
    /// the plain pass would leave the far end applying its own default rather than this node's
    /// instruction, and pinning only the `true` case cannot tell the two apart.
    #[test]
    fn the_escalation_reaches_the_wire_in_both_states() {
        let mut plain = serde_json::json!({ "store_id": store(), "root": root() });
        declare_proxy(&mut plain, false);
        assert_eq!(plain["proxy"], serde_json::json!(false));

        let mut relayed = serde_json::json!({ "store_id": store(), "root": root() });
        declare_proxy(&mut relayed, true);
        assert_eq!(relayed["proxy"], serde_json::json!(true));
    }

    /// **Proves:** the ledger stays bounded by evicting the OLDEST entry only — everything else
    /// keeps its escalation.
    ///
    /// **Fixture design — the survivor must be inserted BEFORE the overflow, not after it.** The
    /// first version of this test filled past the cap and then checked the LAST pair inserted, which
    /// a `clear()`-on-overflow implementation passes trivially: the clear happens at the overflowing
    /// insert, and every entry added afterwards is present again regardless. Confirmed by mutation —
    /// swapping the FIFO `pop_front` for a wholesale clear left that version green. The pair that
    /// distinguishes them is one added early enough to be inside the ledger at the moment of
    /// overflow and NOT the single entry FIFO removes; so the fixture inserts `oldest`, then
    /// `survivor`, fills to exactly the cap, and overflows by ONE.
    ///
    /// The bound is read from `RelayEscalation::MAX_ENTRIES` rather than restated, so the test moves
    /// with the constant instead of pinning a private copy of it.
    ///
    /// **Assertion ORDER is load-bearing too.** `escalate_for` RECORDS on a miss, so checking
    /// `oldest` re-inserts it, overflows the ledger a second time, and evicts `survivor` — the
    /// survivor assertion has to run first, or it measures the damage the line above it did.
    #[test]
    fn the_ledger_evicts_only_the_oldest_entry() {
        let escalation = RelayEscalation::default();
        let (store, root) = (store(), root());
        let oldest = format!("{:064x}", 0);
        let survivor = format!("{:064x}", 1);

        assert!(!escalation.escalate_for(&store, &root, &oldest));
        assert!(!escalation.escalate_for(&store, &root, &survivor));
        // Fill to EXACTLY the cap (the two above included), then overflow by one.
        for n in 2..RelayEscalation::MAX_ENTRIES {
            assert!(!escalation.escalate_for(&store, &root, &format!("{n:064x}")));
        }
        let overflowing = format!("{:064x}", RelayEscalation::MAX_ENTRIES);
        assert!(!escalation.escalate_for(&store, &root, &overflowing));

        assert!(
            escalation.escalate_for(&store, &root, &survivor),
            "a pair that was in the ledger at the moment of overflow and is not the oldest must \
             keep its escalation; discarding the whole ledger would disable the second pass for \
             every live pull at once"
        );
        assert!(
            !escalation.escalate_for(&store, &root, &oldest),
            "the OLDEST pair is the one evicted, so it starts plain again - one wasted plain round \
             for a capsule this node stopped working on, never an unbounded map"
        );
    }
}
