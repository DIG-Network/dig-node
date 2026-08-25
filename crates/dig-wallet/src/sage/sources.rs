//! The node's chain SOURCES: the ONE place a chia peer fabric is constructed, and the
//! [`ProviderRegistry`] that names every source it holds (dig_ecosystem#2790, dig-node#249).
//!
//! # Why this module exists at all
//!
//! NC-12's third acceptance clause reads *"no path constructs its own peer fabric outside the
//! registry"*. It used to hold for the worst possible reason: **there was no registry.**
//! `chia_query::provider_registry::ProviderRegistry` had no production construction site anywhere
//! in dig-node, so the clause was satisfied by the absence of the thing it governs — a property
//! nobody could violate because nobody could exercise it.
//!
//! [`NodeChainSources`] makes it a real property. It owns the lazily-built
//! [`chia_query::ChiaQuery`] fabric, it is the only production caller of `ChiaQuery::new`, and it
//! registers what it built. Every production path that wants chain data asks [`NodeChainSources`]
//! for the fabric ([`NodeChainSources::client`]); a path that builds its own is a second, unnamed
//! trust domain, and `sole_owner_tests` below fails on one.
//!
//! # WHAT ENFORCES THE CLAUSE TODAY: the sweep, not the registry
//!
//! State this plainly, because NC-12's "Satisfied by" record is written from here and an
//! overstatement here becomes the ecosystem's record of a discharged obligation:
//!
//! * **The enforcement is `sole_owner_tests`.** It fails when a second `ChiaQuery::new` appears in
//!   production code anywhere in this crate that its classifier can SEE — a CI gate over the
//!   source, and what makes the clause a property rather than an absence. It is a heuristic, not a
//!   parse: `sweep` names every shape it mis-reads and the direction each one fails in, and it
//!   refuses outright on a file it could not finish classifying.
//! * **The registry gives the sweep its target**, by being the thing the one permitted construction
//!   registers into. Registering does not make the registry a control.
//! * **Nothing in production reads the registry.** [`NodeChainSources::registry`] has no production
//!   caller at this revision: `ChainTransport` asks only for [`NodeChainSources::client`], and no
//!   production path calls [`ProviderRegistry::trusted`] or [`ProviderRegistry::any`]. The
//!   enumeration and the trust classification are a declared INVENTORY.
//! * **The read that genuinely removed the third party is elsewhere** — the corroborated peak in
//!   [`super::peer_reads`], reached from the only production `ChainTransport`. That one is consumed
//!   on every peak read, and it is this module's neighbour rather than its content.
//!
//! # What the registry OWNS, and what it deliberately does not
//!
//! It owns the ENUMERATION and the TRUST CLASSIFICATION of the node's chain sources — which
//! sources exist, which independence group each belongs to, and what each would be allowed to
//! decide. Both registered sources are untrusted (their kinds default that way) and
//! `allow_public_quorum_custody` is left OFF, so the custody view
//! ([`ProviderRegistry::trusted`]) **fails closed** — no public oracle and no randomly dialled peer
//! could decide where money goes merely by answering first. Read that as a PRE-CONDITION the first
//! consumer will inherit, not as a gate standing in a live read path: with no production reader,
//! nothing today is refused by it.
//!
//! Being correct before it is consumed is the point. The classification is derived from what the
//! sources can actually REACH, not from what they are called — see [`independence_group_for`] — and
//! a quorum counts distinct independence groups, so a group id that overstates independence would
//! convert a 2-of-2 quorum into one endpoint answering twice. That defect was real here, and a
//! future consumer would have inherited it silently.
//!
//! It does NOT own the peer sessions that carry a corroborated read. Those are drawn
//! independently by [`super::peer_reads::DialedPeerSample`] and by
//! [`super::sync_supervisor::ChiaQuorumCorroborator`], on purpose: NC-12 asks for AGREEMENT across
//! several concurrently-held sessions, and a registry that collapsed them into one connection
//! would unify the owner by destroying the plurality. **One dialler is the goal; one voice is a
//! regression.**
//!
//! # Try-order, and what it does NOT buy
//!
//! The peer provider registers at [`PEER_PROVIDER_PRIORITY`], ahead of coinset's, so the discovery
//! view asks it first. That orders the two REGISTRATIONS; it cannot reorder what happens inside
//! the first one. `chia-query`'s router asks `api.coinset.org` FIRST and consults this node's
//! peers only when that fails, so a read served by the peer provider is still a third party's view
//! of the chain even on a node holding five peers.
//!
//! The read that genuinely removed the third party is the corroborated peak in
//! [`super::peer_reads`], which reads held peer streams and never falls through to an oracle. The
//! registry's contribution is honest ENUMERATION and honest CLASSIFICATION of what remains — which
//! is why the peer provider is grouped with the oracle while it is backed by a coinset-first
//! router.

use std::borrow::Cow;
use std::sync::Arc;

use chia_query::provider_registry::interface::{ProviderId, ProviderInfo, ProviderKind};
use chia_query::provider_registry::{ChiaQueryProvider, CoinsetProvider, ProviderRegistry};
use chia_query::{ChiaQuery, ChiaQueryConfig};
use tokio::sync::Mutex;

use super::{Error, Result};

/// Try-order priority for this node's own Chia peers — ahead of the public oracle's.
///
/// A number rather than an ordering enum because that is what [`ProviderInfo::priority`] is. It is
/// lower than chia-query's coinset priority for the reason in the module docs, and the gap below
/// it is wide enough that an operator-supplied source can be slotted in front.
pub const PEER_PROVIDER_PRIORITY: i32 = 5;

/// The independence group this node's dialled Chia peers belong to.
///
/// Sources that could fail or lie TOGETHER share a group. Every session in the fabric is dialled
/// through one discovery path under one TLS identity, so the fabric is ONE group however many
/// peers it holds — counting it as several would let a quorum be satisfied by a single dialler.
pub const PEER_INDEPENDENCE_GROUP: &str = "chia-peers";

/// This node's peer provider's ID — its NAME in the registry, which is not its trust grouping.
///
/// Kept distinct from the independence group because the two answer different questions: the id
/// says which provider answered, the group says who else it could be lying with.
pub const PEER_PROVIDER_ID: &str = "chia-peers";

/// The independence group of the public coinset oracle.
pub const ORACLE_INDEPENDENCE_GROUP: &str = "coinset.org";

/// The config every production fabric is built from — the one place its shape is decided.
///
/// Named rather than inlined because [`independence_group_for`] classifies the fabric from it: a
/// future change to what the fabric may reach must move its trust classification with it, and it
/// can only do that if both read the same value.
fn client_config() -> ChiaQueryConfig {
    ChiaQueryConfig::default()
}

/// The independence group a peer provider backed by `cfg` belongs to.
///
/// # Why this is derived rather than declared
///
/// chia-query's quorum counts DISTINCT independence groups, and its own definition of a group is
/// *"sources that could fail or lie together — e.g. two views of the same coinset.org"*. A
/// `ChiaQuery` built with `coinset_fallback_enabled` asks `api.coinset.org` first and consults its
/// peers only when that fails, so such a fabric IS a view of coinset.org — however many peers it
/// holds. Registering it as its own group made a 2-of-2 independent-group custody quorum
/// satisfiable by one HTTPS endpoint: measured on a `max_peers: 0` client, which holds no peers at
/// all, the custody view returned a peak. Naming the group after the provider TYPE rather than
/// after what it can reach is what made that possible.
///
/// So: a fabric that can fall through to the oracle shares the oracle's group, and only a fabric
/// that cannot is counted as an independent peer source. The property this establishes is that two
/// providers counted as independent cannot both be satisfied by the same endpoint.
#[must_use]
pub fn independence_group_for(cfg: &ChiaQueryConfig) -> &'static str {
    if cfg.coinset_fallback_enabled {
        ORACLE_INDEPENDENCE_GROUP
    } else {
        PEER_INDEPENDENCE_GROUP
    }
}

/// The node's chain sources: one peer fabric, and the registry that names it.
///
/// Built LAZILY. Constructing the fabric dials the network, and a node whose operator never opens
/// a wallet surface should make no such call — so nothing here dials until something asks. A
/// FAILED build is never cached as a permanent verdict: a node that was offline at 9am must be
/// able to answer at 10am.
pub struct NodeChainSources {
    /// `None` until the first use builds it.
    client: Mutex<Option<Arc<ChiaQuery>>>,
    /// The independence group the fabric is registered in, decided by what it can REACH.
    peer_group: &'static str,
}

impl Default for NodeChainSources {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeChainSources {
    /// Sources that have not dialled anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Mutex::new(None),
            peer_group: independence_group_for(&client_config()),
        }
    }

    /// Sources that already HOLD `client`, so nothing dials.
    ///
    /// Seeding is what makes pointer identity assertable: a consumer that quietly built its own
    /// fabric returns a different `Arc`, which no agreement-based assertion could tell apart from
    /// sharing — two pools that happened to pick the same peers agree too.
    ///
    /// A fabric handed in from outside carries no description of what it can reach, so it is
    /// classified CONSERVATIVELY: it shares the oracle's independence group. Guessing the other
    /// way would let a caller manufacture independence by construction, which is the failure this
    /// classification exists to remove.
    #[must_use]
    pub fn with_client(client: Arc<ChiaQuery>) -> Self {
        Self {
            client: Mutex::new(Some(client)),
            peer_group: ORACLE_INDEPENDENCE_GROUP,
        }
    }

    /// The shared fabric, building it on first use.
    ///
    /// **This is the only production call of `ChiaQuery::new` in the crate**, and
    /// `sole_owner_tests` fails if a second one appears.
    pub async fn client(&self) -> Result<Arc<ChiaQuery>> {
        let mut slot = self.client.lock().await;
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let built = Arc::new(
            ChiaQuery::new(client_config())
                .await
                .map_err(|e| Error::internal(format!("no chain source could be reached: {e}")))?,
        );
        *slot = Some(built.clone());
        Ok(built)
    }

    /// The fabric if one already exists, WITHOUT building one.
    ///
    /// Reporting how many peers a node holds must not be the act that makes it hold them.
    pub async fn existing_client(&self) -> Option<Arc<ChiaQuery>> {
        self.client.lock().await.clone()
    }

    /// Drop the held fabric if it is still `client`, so the next caller redials.
    ///
    /// Guarded on identity rather than on emptiness: a fabric somebody else has since built is
    /// never thrown away by a caller acting on a stale observation.
    pub async fn discard_if_current(&self, client: &Arc<ChiaQuery>) {
        let mut slot = self.client.lock().await;
        if slot.as_ref().is_some_and(|held| Arc::ptr_eq(held, client)) {
            *slot = None;
        }
    }

    /// The registry describing the sources this node holds.
    ///
    /// **It has no production caller at this revision** — every caller is test code, and the
    /// module docs say why that is worth stating rather than glossing. Treat what it returns as a
    /// correct inventory awaiting its first reader, not as a gate a live read passes through.
    ///
    /// # Why this is BUILT per call rather than held
    ///
    /// `ProviderRegistry` composes `dyn ChainSourceProvider` values, which chia-query does not
    /// bound `Send + Sync` — its providers are a synchronous, blocking facade by design. Holding
    /// one in a field would make [`NodeChainSources`] itself non-`Sync` and would infect every
    /// async caller of the transport. Building it is cheap: it boxes two wrappers around the
    /// fabric that already exists, and dials nothing.
    ///
    /// The peer provider wraps the SAME `Arc` [`Self::client`] hands out — registering a separate
    /// fabric here would create precisely the second trust domain this module exists to prevent.
    ///
    /// # Runtime requirement
    ///
    /// [`ChiaQueryProvider`] bridges chia-query's async reads to the synchronous `ChainSource`
    /// interface and needs a MULTI-THREAD runtime handle to do it; on a current-thread runtime its
    /// reads fail closed with a clear error rather than deadlocking. Registration itself is
    /// runtime-agnostic, so building the registry is always safe.
    pub async fn registry(&self) -> Result<ProviderRegistry> {
        self.registry_with_public_quorum_custody(false).await
    }

    /// The registry, with chia-query's pure-public-quorum custody rule set explicitly.
    ///
    /// Production always passes `false`: custody must be decided by an operator-trusted source, not
    /// by two public sources agreeing. The parameter exists because the `true` case is the one that
    /// can be WRONG — it is where an overstated independence group turns into a custody answer —
    /// and a property that is only reachable through a flag nobody can set is a property nobody can
    /// test. See `independence_tests` below.
    async fn registry_with_public_quorum_custody(
        &self,
        allow_public_quorum_custody: bool,
    ) -> Result<ProviderRegistry> {
        let client = self.client().await?;

        let peers = ChiaQueryProvider::new(
            client,
            tokio::runtime::Handle::current(),
            ProviderInfo {
                id: ProviderId(Cow::Borrowed(PEER_PROVIDER_ID)),
                kind: ProviderKind::DigPeers,
                priority: PEER_PROVIDER_PRIORITY,
                // What makes a coin read sound here is the corroborated round in
                // `super::peer_reads`, not a flag set at registration.
                trustless: false,
            },
        );
        let oracle = CoinsetProvider::from_env()
            .map_err(|e| Error::internal(format!("coinset provider unavailable: {e}")))?;

        Ok(ProviderRegistry::new()
            .allow_public_quorum_custody(allow_public_quorum_custody)
            .register(Box::new(peers), None, self.peer_group)
            .register(Box::new(oracle), None, ORACLE_INDEPENDENCE_GROUP))
    }
}

#[cfg(test)]
mod independence_tests {
    //! Two providers counted as INDEPENDENT must not be satisfiable by the same endpoint.
    //!
    //! chia-query's quorum counts distinct independence groups, so a group id that overstates
    //! independence does not merely mislabel a source — it lets one endpoint answer twice and
    //! satisfy a 2-of-2 custody quorum by itself. That is what this module pins.

    use super::*;
    use chia_query::provider_registry::interface::{ChainSource, ChainSourceError};

    fn multi_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a multi-thread runtime")
    }

    /// A client that holds NO peers, so nothing but the oracle could possibly answer through it.
    async fn peerless_client() -> Arc<ChiaQuery> {
        Arc::new(
            ChiaQuery::new(ChiaQueryConfig {
                max_peers: 0,
                ..client_config()
            })
            .await
            .expect("a zero-peer client with the coinset tier enabled always constructs"),
        )
    }

    /// The classification tracks what the fabric can REACH, in both directions.
    ///
    /// Both directions are asserted because a classifier that answered "coinset.org" for everything
    /// would satisfy the safety half while destroying the point: a genuinely peers-only fabric must
    /// still count as an independent source.
    #[test]
    fn a_fabric_that_can_reach_the_oracle_is_grouped_with_the_oracle() {
        let coinset_first = ChiaQueryConfig {
            coinset_fallback_enabled: true,
            ..ChiaQueryConfig::default()
        };
        let peers_only = ChiaQueryConfig {
            coinset_fallback_enabled: false,
            ..ChiaQueryConfig::default()
        };

        assert_eq!(
            independence_group_for(&coinset_first),
            ORACLE_INDEPENDENCE_GROUP,
            "a fabric whose router asks api.coinset.org first is a VIEW of coinset.org, so \
             counting it as its own independence group lets one endpoint satisfy a 2-of-2 quorum"
        );
        assert_eq!(
            independence_group_for(&peers_only),
            PEER_INDEPENDENCE_GROUP,
            "a fabric that cannot fall through to the oracle is a genuinely independent source and \
             must still be counted as one"
        );
    }

    /// The production fabric is the coinset-first one, so the registry inherits the oracle's group.
    ///
    /// This is the link that makes the classifier load-bearing rather than decorative: it reads the
    /// same [`client_config`] that [`NodeChainSources::client`] builds from, so flipping the
    /// production config moves the trust classification with it instead of leaving a stale label.
    #[test]
    fn the_production_fabric_is_classified_from_the_config_it_is_built_with() {
        assert!(
            client_config().coinset_fallback_enabled,
            "this test describes the coinset-first fabric; if the production config becomes \
             peers-only, the grouping below changes with it and this file should say so"
        );
        assert_eq!(
            NodeChainSources::new().peer_group,
            ORACLE_INDEPENDENCE_GROUP,
            "the registered peer provider must share the oracle's group while the fabric behind it \
             asks the oracle first"
        );
        let external = multi_thread().block_on(async { peerless_client().await });
        assert_eq!(
            NodeChainSources::with_client(external).peer_group,
            ORACLE_INDEPENDENCE_GROUP,
            "a fabric handed in from outside describes nothing about what it can reach, so it must \
             be grouped conservatively"
        );
    }

    /// One endpoint must not be able to satisfy a 2-of-2 independent-group custody quorum.
    ///
    /// The client holds ZERO peers, so the only thing that can answer either registration is
    /// api.coinset.org. Before the grouping fix this returned `Ok(Some(peak))` from a node with no
    /// peers at all — a "quorum" of one HTTPS endpoint counted twice.
    ///
    /// # What this test can and cannot see
    ///
    /// On a machine that cannot reach api.coinset.org, the pre-fix code also refuses, and this
    /// assertion passes for the wrong reason. That is why it is PAIRED with the two classification
    /// tests above, which need no network and pin the mechanism rather than the outcome.
    #[test]
    fn public_quorum_custody_cannot_be_satisfied_by_a_single_endpoint() {
        let rt = multi_thread();
        let registry = rt.block_on(async {
            let sources = NodeChainSources::with_client(peerless_client().await);
            sources
                .registry_with_public_quorum_custody(true)
                .await
                .expect("the registry needs no network")
        });

        let refusal = registry.trusted().peak_height().expect_err(
            "a node holding ZERO peers has only one source that can answer — api.coinset.org — so \
             a quorum requiring two INDEPENDENT groups must not be satisfiable",
        );
        assert!(
            matches!(refusal, ChainSourceError::NoProvider),
            "the refusal must come from the quorum rule (too few independent groups), not from a \
             provider-level failure; got {refusal:?}"
        );
    }
}

#[cfg(test)]
mod sole_owner_tests {
    use std::path::{Path, PathBuf};

    /// The file that is allowed to construct the fabric.
    const OWNER: &str = "sources.rs";

    /// The call that constructs a chia peer fabric.
    const CONSTRUCTOR: &str = "ChiaQuery::new(";

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read the crate's own source tree") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// What sweeping one file's text found, and whether the sweep could still TELL at the end.
    ///
    /// `ended_inside_a_test_item` is the fail-CLOSED signal: it means the classifier latched into
    /// test code and never saw the item end, so everything after that point was assumed to be test
    /// code without evidence. A file in that state is not "clean", it is UNREAD, and
    /// [`only_the_registry_owner_constructs_a_peer_fabric`] refuses on it rather than reporting a
    /// green it did not earn. That distinction is the whole reason this is a struct and not a
    /// `Vec<usize>`: the previous version could only say "no strays", which reads identically
    /// whether the file was clean or invisible.
    struct Swept {
        /// 1-based line numbers of PRODUCTION calls to `CONSTRUCTOR`.
        sites: Vec<usize>,
        /// The text ran out while still inside a `#[cfg(test)]` item.
        ended_inside_a_test_item: bool,
    }

    /// Whether `line` ends a top-level item, judged only at column 0.
    ///
    /// Rust items introduced by a column-0 attribute close at column 0, and a column-0 line ending
    /// in `}` or `;` is the end of one — a block's own closing brace, a one-line item
    /// (`#[cfg(test)] use …;`), or a whole item written on ONE line (`#[cfg(test)] fn helper() {}`).
    /// Anything indented is still inside the item.
    ///
    /// The one-line block is why this tests "ends with `}`" rather than "IS `}`". Requiring the
    /// bare brace missed `fn helper() {}`, `mod probe {}` and `impl X {}` — each of which left the
    /// latch set for the rest of the file AND left [`Swept::ended_inside_a_test_item`] `false`, so
    /// the sweep went blind and the fail-closed flag did not fire. `rustfmt` preserves those
    /// one-liners, so formatting does not suppress the shape. No file in this crate has it today;
    /// the guard is written for the file somebody adds tomorrow.
    ///
    /// Column 0 is the entire mechanism, and it is what makes this immune to the defect it
    /// replaces. Counting braces meant counting them inside STRING LITERALS, and the crate's
    /// ordinary malformed-JSON fixture (`"{ not json"`) leaves the balance permanently positive —
    /// five of this crate's files never cleared the latch again, so each was blind from its first
    /// column-0 `#[cfg(test)]` to EOF. Literal CONTENT is almost always indented, so refusing to
    /// look at it is both simpler and stricter than trying to parse it out.
    fn ends_a_column_0_item(line: &str) -> bool {
        let trimmed = line.trim_end();
        let at_column_0 = !trimmed.starts_with(char::is_whitespace) && !trimmed.is_empty();
        at_column_0 && (trimmed.ends_with('}') || trimmed.ends_with(';'))
    }

    /// Sweep `text` for PRODUCTION calls to `CONSTRUCTOR`.
    ///
    /// # How test code is recognised, and why this shape
    ///
    /// A `#[cfg(test)]` attribute **at column 0** latches the sweep into test code, and the latch
    /// clears at the next column-0 item end ([`ends_a_column_0_item`]). Both halves are
    /// load-bearing, and each was a measured defect rather than a hypothetical:
    ///
    /// * Latching on ANY `#[cfg(test)]` blinded the sweep to a whole file from the first INDENTED
    ///   one. `chain.rs` gates a test helper inside `impl ChainTransport` at line 157, so lines
    ///   158-711 — `peak_height()`, `push()`, the `ChainFallback` impl, the natural home of the
    ///   very regression this guard names — were invisible, and a live second fabric compiled into
    ///   `ChainTransport::peak_height` left this test green.
    /// * A latch that cleared on BRACE BALANCE counted braces inside string literals, so the
    ///   crate's routine malformed-JSON fixtures held it set to EOF in five files, `rpc.rs` — the
    ///   crate's largest production file — among them. A column-0 production `fn` appended to any
    ///   of them was read as test code and passed the sweep.
    ///
    /// # What it is, and how it fails
    ///
    /// This is a HEURISTIC, not a parse, and it is written so that every imprecision fails LOUDLY:
    ///
    /// * An indented `#[cfg(test)]` does not latch, so a constructor inside a small gated helper is
    ///   reported as production and fails here. Noisy; answered by moving the helper into a
    ///   column-0 test module.
    /// * A `}` or a `;` at column 0 INSIDE a multi-line string literal clears the latch early, so
    ///   the rest of a test module is read as production. Also noisy, also loud.
    /// * A `#[cfg(test)]` item written entirely on one line is classified correctly, but a
    ///   `CONSTRUCTOR` on that same line is reported as PRODUCTION, because the clearing line is
    ///   judged like any other. So `#[cfg(test)] fn f() { ChiaQuery::new(c); }` fails here. Loud,
    ///   and answered by moving it into a column-0 test module — the same trade as the indented
    ///   attribute above.
    /// * A column-0 `#[cfg(test)]` item that never appears to close is not silent either:
    ///   [`Swept::ended_inside_a_test_item`] reports it and the assertion REFUSES. When this
    ///   classifier cannot tell, it says so instead of returning nothing.
    ///
    /// # The one shape that IS silent
    ///
    /// A `#[cfg(test)]` appearing at column 0 as STRING CONTENT — inside a multi-line or raw
    /// literal — latches the sweep on text that is not code. Production lines after it are then
    /// read as test code and dropped, and since the next column-0 line usually does end an item,
    /// the fail-closed flag does not fire either. It is silent, which is the direction that
    /// matters, and it is left unhandled deliberately: detecting it needs literal tracking, which
    /// is the brace-counting mistake in another costume. No occurrence exists in this crate; one
    /// would need a source file that quotes Rust attributes at column 0.
    ///
    /// Taking `&str` rather than walking files is deliberate: it is what lets the fixture tests pin
    /// the classification against shapes chosen to break it, instead of against whatever this
    /// crate's own sources happen to look like today.
    fn sweep(text: &str) -> Swept {
        let mut sites = Vec::new();
        let mut in_test_item = false;
        for (ix, line) in text.lines().enumerate() {
            if in_test_item {
                if !ends_a_column_0_item(line) {
                    continue;
                }
                // The clearing line is the item's LAST line, and a whole item can be written on
                // it. Falling through to the check below, rather than skipping the line, is what
                // makes a constructor on a one-line test item fail loudly instead of vanishing
                // along with the line that cleared the latch.
                in_test_item = false;
            } else if line.starts_with("#[cfg(test)]") {
                in_test_item = true;
                continue;
            }
            if line.contains(CONSTRUCTOR) {
                sites.push(ix + 1);
            }
        }
        Swept {
            sites,
            ended_inside_a_test_item: in_test_item,
        }
    }

    /// Every PRODUCTION call site of `CONSTRUCTOR` in this crate, as `file:line`.
    ///
    /// # Scope, stated so it is not overstated
    ///
    /// It walks `dig-wallet/src` ONLY. A fabric constructed in another crate — `dig-node-core`, a
    /// bin target — is invisible to it. No such site exists today, and this guard is not what
    /// proves that; what it proves is that within the crate owning the wallet's chain access, one
    /// file builds the fabric.
    fn production_call_sites() -> (Vec<String>, Vec<String>) {
        let mut files = Vec::new();
        rust_files(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
            &mut files,
        );
        files.sort();

        let mut sites = Vec::new();
        let mut unread = Vec::new();
        for file in files {
            let name = file
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&file).expect("read a source file");
            let swept = sweep(&text);
            if swept.ended_inside_a_test_item {
                unread.push(name.clone());
            }
            for line_no in swept.sites {
                sites.push(format!("{name}:{line_no}"));
            }
        }
        (sites, unread)
    }

    /// An indented `#[cfg(test)]` must not blind the sweep to the rest of its file.
    ///
    /// The fixture is `chain.rs`'s real shape in miniature: a gated helper inside an `impl`, then
    /// ordinary production code that builds a fabric, then a column-0 test module that legitimately
    /// builds one. Against the latch-on-any-`#[cfg(test)]` classifier the production site at line 6
    /// is silently dropped and this returns empty — which is exactly how a live second fabric in
    /// `ChainTransport::peak_height` passed the sole-owner assertion.
    #[test]
    fn an_indented_cfg_test_does_not_blind_the_sweep() {
        // The construction lines are BUILT from `CONSTRUCTOR` rather than written out, so this
        // file never contains the needle it sweeps for. A source-scanning test that spells its own
        // needle finds itself, and its verdict then describes the test rather than the crate.
        let fixture = [
            "impl ChainTransport {".to_string(),
            "    #[cfg(test)]".to_string(),
            "    fn with_client(c: Arc<Q>) -> Self { Self { c } }".to_string(),
            String::new(),
            "    async fn peak_height(&self) -> u32 {".to_string(),
            format!("        let rogue = {CONSTRUCTOR}cfg).await;"),
            "        rogue.peak()".to_string(),
            "    }".to_string(),
            "}".to_string(),
            "#[cfg(test)]".to_string(),
            "mod tests {".to_string(),
            format!("    fn client() {{ {CONSTRUCTOR}cfg); }}"),
            "}".to_string(),
        ]
        .join("\n");

        assert_eq!(
            sweep(&fixture).sites,
            vec![6],
            "the sweep must SEE the production construction at line 6 — inside an `impl` that also \
             holds an INDENTED `#[cfg(test)]` helper — and must NOT see the one at line 12, inside \
             a column-0 test module. Reporting neither is the vacuity that let a live second peer \
             fabric pass this guard."
        );
    }

    /// The latch CLEARS at the end of a test module, so production code below one is still swept
    /// — and it must still clear when that module holds a string literal containing a stray brace.
    ///
    /// The unbalanced `"{ not json"` is the point of this fixture, not decoration. It is the
    /// crate's ordinary malformed-input idiom, present today in `rpc.rs`, `tipping.rs`, `types.rs`,
    /// `watchlist.rs` and `autoseed.rs`, and against a brace-COUNTING classifier it holds the latch
    /// set past the module's end: the production site at line 5 goes unreported, this returns
    /// empty, and a second peer fabric anywhere below `rpc.rs:4783` passes the sweep. An earlier
    /// version of this test used a brace-BALANCED fixture and so could not express the shape at
    /// all — it proved the latch CAN clear, never that it does on any file this crate contains.
    #[test]
    fn a_stray_brace_in_a_test_fixture_does_not_hide_the_production_code_below_it() {
        let fixture = [
            "#[cfg(test)]".to_string(),
            "mod tests {".to_string(),
            r#"    fn rejects_garbage() { parse("{ not json"); }"#.to_string(),
            "}".to_string(),
            format!("fn later() {{ {CONSTRUCTOR}cfg); }}"),
        ]
        .join("\n");

        assert_eq!(
            sweep(&fixture).sites,
            vec![5],
            "a test module holding an unbalanced brace inside a STRING must not hide every line \
             beneath it; this is the shape that made five of this crate's files invisible from \
             their first column-0 `#[cfg(test)]` to their end"
        );
    }

    /// A `#[cfg(test)]` item written on ONE line ends there, and does not swallow the file.
    ///
    /// `fn helper() {}` is at column 0 and ends with `}`, but it is not the bare `}` an earlier
    /// version of [`ends_a_column_0_item`] required — so the latch stayed set for the rest of the
    /// file. That shape defeated BOTH of the previous round's remedies at once: the sweep went
    /// blind (the production site at line 4 was dropped) and `ended_inside_a_test_item` stayed
    /// `false`, so the fail-closed refusal never fired either. `rustfmt` preserves such one-liners,
    /// so `cargo fmt` does not suppress it. `mod probe {}` and `impl X {}` are the same shape.
    ///
    /// The one-line item's OWN construction is asserted too, on line 6: it is reported as
    /// production, deliberately and loudly, because the clearing line is judged like any other.
    #[test]
    fn a_one_line_test_item_does_not_swallow_the_rest_of_the_file() {
        let fixture = [
            "#[cfg(test)]".to_string(),
            "fn helper() {}".to_string(),
            String::new(),
            format!("fn later() {{ {CONSTRUCTOR}cfg); }}"),
            "#[cfg(test)]".to_string(),
            format!("fn gated() {{ {CONSTRUCTOR}cfg); }}"),
        ]
        .join("\n");

        let swept = sweep(&fixture);
        assert_eq!(
            swept.sites,
            vec![4, 6],
            "a one-line `#[cfg(test)]` item must end on its own line, leaving line 4 visible as \
             production; and a constructor written ON a one-line test item (line 6) is reported \
             rather than dropped, because that is the loud direction"
        );
        assert!(
            !swept.ended_inside_a_test_item,
            "the latch must not still be set at EOF here — a stuck latch that also reports itself \
             as clean is how this shape defeated both of the previous remedies at once"
        );
    }

    /// A file the sweep could not finish reading is REFUSED, never reported clean.
    ///
    /// An unterminated `#[cfg(test)]` item means every line after it was assumed to be test code
    /// with no evidence. "No strays" from such a file is indistinguishable from "no strays" from a
    /// file that was genuinely read — which is precisely how the previous classifier reported green
    /// over five blind files.
    #[test]
    fn a_file_the_sweep_could_not_finish_reading_is_reported_as_unread() {
        let unterminated = ["#[cfg(test)]".to_string(), "mod tests {".to_string()].join("\n");
        assert!(
            sweep(&unterminated).ended_inside_a_test_item,
            "a `#[cfg(test)]` item that never closes leaves the rest of the file unclassified, and \
             the sweep must SAY so rather than return an empty stray list"
        );

        let terminated = [
            "#[cfg(test)]".to_string(),
            "mod tests {".to_string(),
            "}".to_string(),
        ]
        .join("\n");
        assert!(
            !sweep(&terminated).ended_inside_a_test_item,
            "an ordinary closed test module must not be reported as unread, or every file in the \
             crate refuses and this guard means nothing"
        );
    }

    /// The haystack is real: the sweep can still SEE a call site.
    ///
    /// Without this the sweep below passes just as well against a broken file walk, a renamed
    /// constructor, or a source tree it never read — the failure mode where a guard reports clean
    /// because it looked at nothing.
    #[test]
    fn the_sweep_can_find_a_construction_site_at_all() {
        let mut files = Vec::new();
        rust_files(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
            &mut files,
        );
        let total: usize = files
            .iter()
            .map(|f| {
                std::fs::read_to_string(f)
                    .expect("read a source file")
                    .matches(CONSTRUCTOR)
                    .count()
            })
            .sum();
        assert!(
            total > 0,
            "the sweep found NO `{CONSTRUCTOR}` anywhere in {} files — it is measuring nothing, \
             so the sole-owner assertion below would pass no matter what the code did",
            files.len()
        );
    }

    /// NC-12: *no path constructs its own peer fabric outside the registry*.
    ///
    /// This is the clause that was vacuously satisfied — it held because there was no registry.
    /// It is a real property only while exactly one production site can build a fabric, and that
    /// site is the one that registers what it built.
    ///
    /// What this asserts is bounded by what [`sweep`] can see, and that bound is written down
    /// there rather than assumed away here: it classifies text by column-0 attributes, it names
    /// the shapes it mis-reads together with the direction each fails in, and a file it could not
    /// finish classifying is REFUSED above rather than counted as clean. So read a green here as
    /// "no visible second owner, and nothing was invisible", which is a narrower claim than "no
    /// second owner exists" and is the strongest one a source sweep can make.
    #[test]
    fn only_the_registry_owner_constructs_a_peer_fabric() {
        let (sites, unread) = production_call_sites();
        assert!(
            unread.is_empty(),
            "the sweep never saw a `#[cfg(test)]` item END in these files, so everything below \
             that point was assumed to be test code and a second peer fabric there would be \
             invisible. This guard refuses rather than report a green it did not earn: {unread:?}"
        );
        let strays: Vec<&String> = sites.iter().filter(|s| !s.starts_with(OWNER)).collect();
        assert!(
            strays.is_empty(),
            "these production call sites build their own chia peer fabric outside {OWNER}, so \
             the node holds peer sessions the provider registry has never heard of and the \
             operator's provider configuration cannot reach: {strays:?}"
        );
        assert_eq!(
            sites.len(),
            1,
            "expected exactly one production fabric owner, found {sites:?}"
        );
    }
}

#[cfg(test)]
mod custody_fails_closed_tests {
    //! The registry's custody view REFUSES on a default install.
    //!
    //! What this pins, precisely: the refusal is the TRUST RULE, not emptiness and not a transport
    //! failure. No operator has declared a source their own, so no public oracle and no randomly
    //! dialled peer would be allowed to decide where money goes merely by answering first.
    //!
    //! What it does NOT pin, and must not be read as: that anything in production consults this.
    //! Nothing does at this revision (see the module docs). These tests establish that the object
    //! is correct BEFORE it acquires a consumer — a registry whose custody view accepted a public
    //! oracle would hand its first reader a money-routing answer from one endpoint, and that reader
    //! would have no reason to re-check.

    use super::*;
    use chia_query::provider_registry::interface::{
        ChainSource, ChainSourceError, ChainSourceProvider,
    };

    /// A `ChiaQuery` that dials nothing: `max_peers: 0` leaves the peer tier with nothing to draw,
    /// so it performs no DNS and no TLS handshake. The coinset tier stays enabled only because
    /// chia-query derives `PeerRequirement::Optional` from it, which is what lets a zero-peer
    /// client construct at all.
    /// A multi-thread runtime, because [`ChiaQueryProvider`] bridges async reads to the
    /// synchronous `ChainSource` interface and fails closed on a current-thread one. The registry
    /// is BUILT inside the runtime and READ from the test thread outside it — chia-query SPEC §7's
    /// intended pattern, and the only one available here: `ProviderRegistry` is not `Send`, so it
    /// cannot be handed to `spawn_blocking`.
    fn multi_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a multi-thread runtime")
    }

    async fn offline_client() -> Arc<ChiaQuery> {
        Arc::new(
            ChiaQuery::new(ChiaQueryConfig {
                max_peers: 0,
                coinset_fallback_enabled: true,
                ..Default::default()
            })
            .await
            .expect("a zero-peer client with the coinset tier enabled always constructs"),
        )
    }

    #[test]
    fn the_custody_view_refuses_because_nothing_is_trusted_not_because_nothing_answered() {
        let rt = multi_thread();
        let registry = rt.block_on(async {
            let sources = NodeChainSources::with_client(offline_client().await);
            sources
                .registry()
                .await
                .expect("the registry needs no network")
        });

        let refusal = registry
            .trusted()
            .peak_height()
            .expect_err("a default install has no operator-trusted source, so custody must refuse");

        // The VARIANT is the assertion, not merely that it failed. An unreachable network also
        // produces an `Err`, and a test satisfied by any error would pass just as well against a
        // registry that happily accepted the public oracle for custody and simply could not reach
        // it from a sandbox — which is the opposite property.
        assert!(
            matches!(refusal, ChainSourceError::NoProvider),
            "custody must refuse on the TRUST rule (no trusted source, public-quorum custody off), \
             not on a transport failure; got {refusal:?}"
        );
    }

    #[test]
    fn both_registered_sources_are_present_and_the_node_s_peers_are_tried_first() {
        let rt = multi_thread();
        let registry = rt.block_on(async {
            let sources = NodeChainSources::with_client(offline_client().await);
            sources
                .registry()
                .await
                .expect("the registry needs no network")
        });

        // chia-query gives the oracle a higher (later) priority number than this node's peers, so
        // the discovery view asks the peers first — the inversion of the router's own
        // coinset-first ordering. Asserted as a comparison rather than against a literal so a
        // change in chia-query's constant fails here loudly instead of silently reordering.
        let oracle_priority = CoinsetProvider::from_env()
            .expect("the coinset provider needs no network to describe itself")
            .provider_info()
            .priority;
        assert!(
            PEER_PROVIDER_PRIORITY < oracle_priority,
            "this node's own peers must be tried before the public oracle, but the peer priority \
             {PEER_PROVIDER_PRIORITY} is not ahead of the oracle's {oracle_priority}"
        );

        // And the registry really HOLDS providers, so the ordering above orders things that exist
        // rather than comparing two constants.
        //
        // The discriminator is the VARIANT, and it is the same one however the machine running
        // this test is connected: an EMPTY registry answers `NoProvider` because it had nothing to
        // ask, while a populated one either answers or reports how the ask failed. A discovery
        // read that is anything other than `NoProvider` therefore proves a provider was tried —
        // with a network or without one, which is why this test needs neither.
        let discovery = registry.any().peak_height();
        assert!(
            !matches!(discovery, Err(ChainSourceError::NoProvider)),
            "the discovery view reported an EMPTY registry: nothing was registered, so the \
             priority ordering above orders nothing and the custody refusal above is emptiness \
             rather than the trust rule"
        );
    }
}
