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
//! registers what it built. A path that wants chain data asks it; a path that builds its own is a
//! second, unnamed trust domain, and `sole_owner_tests` below fails on one.
//!
//! # What the registry OWNS, and what it deliberately does not
//!
//! It owns the ENUMERATION and the TRUST CLASSIFICATION of the node's chain sources — which
//! sources exist, which independence group each belongs to, and what each is allowed to decide.
//! Both registered sources are untrusted (their kinds default that way) and
//! `allow_public_quorum_custody` is left OFF, so the custody view
//! ([`ProviderRegistry::trusted`]) **fails closed** on a default install: no public oracle and no
//! randomly dialled peer may decide where money goes merely by answering first.
//!
//! It does NOT own the peer sessions that carry a corroborated read. Those are drawn
//! independently by [`super::peer_reads::DialedPeerSample`] and by
//! [`super::sync_supervisor::ChiaQuorumCorroborator`], on purpose: NC-12 asks for AGREEMENT across
//! several concurrently-held sessions, and a registry that collapsed them into one connection
//! would unify the owner by destroying the plurality. **One dialler is the goal; one voice is a
//! regression.**
//!
//! # Try-order: this node's peers before the oracle
//!
//! The peer provider registers at [`PEER_PROVIDER_PRIORITY`], ahead of coinset's. `chia-query`'s
//! own router asks `api.coinset.org` FIRST and consults this node's peers only when that fails, so
//! a read taken straight off the router is a third party's view of the chain even on a node
//! holding five peers. The registry's discovery view inverts that: the node's own peers answer,
//! and the oracle is what is left when they cannot.

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

/// The independence group of the public coinset oracle.
pub const ORACLE_INDEPENDENCE_GROUP: &str = "coinset.org";

/// The node's chain sources: one peer fabric, and the registry that names it.
///
/// Built LAZILY. Constructing the fabric dials the network, and a node whose operator never opens
/// a wallet surface should make no such call — so nothing here dials until something asks. A
/// FAILED build is never cached as a permanent verdict: a node that was offline at 9am must be
/// able to answer at 10am.
pub struct NodeChainSources {
    /// `None` until the first use builds it.
    client: Mutex<Option<Arc<ChiaQuery>>>,
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
        }
    }

    /// Sources that already HOLD `client`, so nothing dials.
    ///
    /// Seeding is what makes pointer identity assertable: a consumer that quietly built its own
    /// fabric returns a different `Arc`, which no agreement-based assertion could tell apart from
    /// sharing — two pools that happened to pick the same peers agree too.
    #[must_use]
    pub fn with_client(client: Arc<ChiaQuery>) -> Self {
        Self {
            client: Mutex::new(Some(client)),
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
            ChiaQuery::new(ChiaQueryConfig::default())
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
        let client = self.client().await?;

        let peers = ChiaQueryProvider::new(
            client,
            tokio::runtime::Handle::current(),
            ProviderInfo {
                id: ProviderId(Cow::Borrowed(PEER_INDEPENDENCE_GROUP)),
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
            .register(Box::new(peers), None, PEER_INDEPENDENCE_GROUP)
            .register(Box::new(oracle), None, ORACLE_INDEPENDENCE_GROUP))
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

    /// The net brace balance a line contributes: `{` opens, `}` closes.
    ///
    /// Braces inside string literals and comments are counted too. That is the one imprecision in
    /// [`production_lines`]' scope tracking, and it is recorded rather than hidden: a stray unpaired
    /// `{` inside a test module keeps the latch set past that module's end (silent under-report),
    /// and a stray unpaired `}` clears it early (loud over-report). Neither shape exists in this
    /// crate today.
    fn brace_balance(line: &str) -> i32 {
        let opens = i32::try_from(line.matches('{').count()).unwrap_or(i32::MAX);
        let closes = i32::try_from(line.matches('}').count()).unwrap_or(i32::MAX);
        opens - closes
    }

    /// The 1-based line numbers at which `text` calls `CONSTRUCTOR` from PRODUCTION code.
    ///
    /// # How test code is recognised, and why this shape
    ///
    /// A `#[cfg(test)]` attribute **at column 0** latches the sweep into test code, and the latch
    /// CLEARS when the item it introduced ends — tracked by brace balance for a block, or by a
    /// trailing `;` for a one-line item. Both halves are load-bearing, and both were defects:
    ///
    /// * Latching on ANY `#[cfg(test)]` blinded the sweep to a whole file from the first INDENTED
    ///   one. `chain.rs` gates a test helper inside `impl ChainTransport` at line 157, so lines
    ///   158-711 — `peak_height()`, `push()`, the `ChainFallback` impl, the natural home of the
    ///   very regression this guard names — were invisible, and a live second fabric compiled into
    ///   `ChainTransport::peak_height` left this test green.
    /// * A latch that never cleared blinded it to every line below a file's first test module, so
    ///   production code beneath one could never be reported.
    ///
    /// This is a HEURISTIC, not a parse, and it is written to fail in the LOUD direction. An
    /// indented `#[cfg(test)]` no longer latches at all, so a constructor inside a small gated
    /// helper is reported as production and fails here — noisy, and answered by moving the helper
    /// into a column-0 test module. The silent direction (a production site read as a test one)
    /// now requires a column-0 `#[cfg(test)]` whose item never appears to close, which is the
    /// imprecision [`brace_balance`] describes.
    ///
    /// Taking `&str` rather than walking files is deliberate: it is what lets
    /// [`an_indented_cfg_test_does_not_blind_the_sweep`] pin the classification against a fixture
    /// instead of against whatever this crate's own sources happen to look like today.
    fn production_lines(text: &str) -> Vec<usize> {
        let mut sites = Vec::new();
        // `Some(depth)` while inside a column-0 `#[cfg(test)]` item; `depth` is the brace balance
        // accumulated since the attribute, so back-to-zero-on-a-close means the item ended.
        let mut in_test_item: Option<i32> = None;
        for (ix, line) in text.lines().enumerate() {
            match in_test_item.as_mut() {
                Some(depth) => {
                    *depth += brace_balance(line);
                    let block_closed = *depth <= 0 && line.contains('}');
                    let one_liner_ended = *depth == 0 && line.trim_end().ends_with(';');
                    if block_closed || one_liner_ended {
                        in_test_item = None;
                    }
                }
                None if line.starts_with("#[cfg(test)]") => in_test_item = Some(0),
                None if line.contains(CONSTRUCTOR) => sites.push(ix + 1),
                None => {}
            }
        }
        sites
    }

    /// Every PRODUCTION call site of `CONSTRUCTOR` in this crate, as `file:line`.
    ///
    /// # Scope, stated so it is not overstated
    ///
    /// It walks `dig-wallet/src` ONLY. A fabric constructed in another crate — `dig-node-core`, a
    /// bin target — is invisible to it. No such site exists today, and this guard is not what
    /// proves that; what it proves is that within the crate owning the wallet's chain access, one
    /// file builds the fabric.
    fn production_call_sites() -> Vec<String> {
        let mut files = Vec::new();
        rust_files(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
            &mut files,
        );
        files.sort();

        let mut sites = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("read a source file");
            for line_no in production_lines(&text) {
                sites.push(format!(
                    "{}:{}",
                    file.file_name().expect("a file name").to_string_lossy(),
                    line_no
                ));
            }
        }
        sites
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
            production_lines(&fixture),
            vec![6],
            "the sweep must SEE the production construction at line 6 — inside an `impl` that also \
             holds an INDENTED `#[cfg(test)]` helper — and must NOT see the one at line 12, inside \
             a column-0 test module. Reporting neither is the vacuity that let a live second peer \
             fabric pass this guard."
        );
    }

    /// The latch CLEARS at the end of a test module, so production code below one is still swept.
    #[test]
    fn production_code_below_a_test_module_is_still_swept() {
        let fixture = [
            "#[cfg(test)]".to_string(),
            "mod tests {".to_string(),
            format!("    fn c() {{ {CONSTRUCTOR}cfg); }}"),
            "}".to_string(),
            format!("fn later() {{ {CONSTRUCTOR}cfg); }}"),
        ]
        .join("\n");

        assert_eq!(
            production_lines(&fixture),
            vec![5],
            "a file's first test module must not hide every line beneath it"
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
    #[test]
    fn only_the_registry_owner_constructs_a_peer_fabric() {
        let sites = production_call_sites();
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
    //! The registry is LOAD-BEARING, not ornamental.
    //!
    //! A registry that exists but decides nothing would satisfy NC-12's wording exactly as
    //! vacuously as having no registry at all — the failure this module was written to end. What
    //! makes it real is that its custody view REFUSES on a default install: no operator has
    //! declared a source their own, so no public oracle and no randomly dialled peer may decide
    //! where money goes merely by answering first.

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
