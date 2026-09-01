//! The capsule warm's dial-candidate locator, tested through the REAL stack
//! (dig_ecosystem#3128 requirement 4).
//!
//! # Why these tests build the production locator instead of a double
//!
//! [`crate::download::NodeContent::provider_locator_chain`] already records the lesson these tests
//! apply: *"Every locator double in the suite used to be handed straight to `NodeContent::new`,
//! which skips layers 1-3 entirely — so a defect living INSIDE them was structurally invisible to
//! every test while being on the only path production takes."*
//!
//! Every existing warmer test builds its own `MockProviderLocator` and hands it to
//! `CapsuleWarmer::new`, so not one of them is on production's path — and the reachability gap below
//! lived exactly there: the warm was wired with the node's DISCOVERY locator, which deliberately
//! excludes the connected pool, so a capsule holder this node was already connected to was invisible
//! to the pull. The fixtures here take their locator from
//! [`crate::download::NodeContent::warm_provider_locator`], which is the handle production uses.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dig_download::testkit::{mock_peer_hex, MockContent, MockProviderLocator, MockRangeTransport};
use dig_download::{DownloadError, ModuleInfo, ModuleTransport};
use digstore_core::Bytes32;

use crate::download::{MissMode, NodeContent};
use crate::seams::dig_peer::{AnnounceHolder, CapsuleWarmer, WarmPaths, WarmRegistry};

/// The store every fixture names.
const STORE: [u8; 32] = [0xa1; 32];
/// The generation root every fixture names. The anchor resolver below confirms exactly this, so the
/// warm reaches its locate step rather than refusing at the chain gate.
const ROOT: [u8; 32] = [0xbb; 32];

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The directory is OWNED by the returned guard: `TempDir`'s `Drop` removes the tree,
/// including on an unwind, so a failing assertion cannot leak it (dig-node#370).
fn temp_dir(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("dig-node-warmloc-{tag}-"))
        .tempdir()
        .expect("tempdir")
}

/// Confirms the fixture generation, so the warm passes its chain gate and reaches the locate step
/// these tests are about.
struct AnchoringChain;

#[async_trait]
impl crate::shared::AnchoredRootResolver for AnchoringChain {
    async fn anchored_root(&self, _store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        Ok(Some(Bytes32(ROOT)))
    }
}

/// Records every peer the module pull asked for a descriptor, then fails the ask.
///
/// Failing is deliberate: what is under test is WHICH peer the engine was able to reach, not whether
/// a capsule lands. A transport that served real bytes would need a faithful `.dig` fixture and
/// would prove nothing extra — the observation is the call, and the call is recorded before it
/// fails.
#[derive(Default)]
struct RecordingModuleTransport {
    asked: Mutex<Vec<String>>,
}

impl RecordingModuleTransport {
    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("recorder lock").clone()
    }
}

#[async_trait]
impl ModuleTransport for RecordingModuleTransport {
    async fn get_module_info(
        &self,
        provider_peer_id: &str,
        _store_id: &str,
        _root: &str,
    ) -> Result<ModuleInfo, DownloadError> {
        self.asked
            .lock()
            .expect("recorder lock")
            .push(provider_peer_id.to_string());
        Err(DownloadError::transport(provider_peer_id, "recorded"))
    }

    async fn fetch_module_range(
        &self,
        provider_peer_id: &str,
        _store_id: &str,
        _root: &str,
        _offset: u64,
        _length: u64,
    ) -> Result<Vec<u8>, DownloadError> {
        Err(DownloadError::transport(provider_peer_id, "recorded"))
    }
}

/// Counts announcements; none of these fixtures reaches one, and asserting that would duplicate
/// `module_reshare`'s own coverage.
#[derive(Default)]
struct SilentAnnounce;

#[async_trait]
impl AnnounceHolder for SilentAnnounce {
    async fn announce_inventory(&self) {}
}

/// A node whose DHT discovery finds NOBODY and whose connected pool holds exactly `pool_peer`.
///
/// **The empty DHT is the load-bearing half of the fixture.** With any DHT provider present, a warm
/// that reached the holder through the DHT and a warm that reached it through the pool are
/// indistinguishable, and the reachability test would pass against the unfixed code. An empty DHT
/// leaves the pool as the only possible source of a candidate.
///
/// The locator is built through [`NodeContent::provider_locator_chain`] — the union, the
/// self-exclusion and the capsule fallback `for_dht` installs — so these fixtures drive the layers
/// production drives.
fn node_with_pool_peer(pool_peer: &str, self_peer_id: Option<String>) -> Arc<NodeContent> {
    let dir = temp_dir("engine");
    let content = NodeContent::new(
        NodeContent::provider_locator_chain(
            Arc::new(MockProviderLocator::fixed(Vec::new())),
            self_peer_id.clone(),
        ),
        Arc::new(MockRangeTransport::new(MockContent::even(4, 1))),
        MissMode::Redirect,
        self_peer_id,
        &dir,
    );
    content.connected_pool().lock().expect("pool lock").insert(
        pool_peer.to_string(),
        vec!["10.0.0.9:9444".parse::<SocketAddr>().expect("test address")],
    );
    content
}

/// A warmer built over `content`'s PRODUCTION warm locator and a recording transport.
fn warmer_over(
    content: &Arc<NodeContent>,
    transport: Arc<RecordingModuleTransport>,
    dir: &std::path::Path,
) -> Arc<CapsuleWarmer> {
    CapsuleWarmer::new(
        content.warm_provider_locator(),
        transport,
        Arc::new(crate::seams::dig_peer::NoPullState),
        Arc::new(dig_download::InMemoryStateStore::new()),
        Arc::new(AnchoringChain),
        WarmPaths {
            staging_dir: dir.join("staging"),
            cache_dir: dir.join("cache"),
        },
        Arc::new(SilentAnnounce),
        Arc::new(WarmRegistry::new()),
        dig_download::ModuleDownloadConfig::default(),
        Arc::new(crate::tier0_live::NoopModulesEvictor),
    )
}

/// **Proves:** a capsule warm reaches a holder that is only reachable through the CONNECTED POOL —
/// the DHT names nobody, and the pull still issues `getModuleInfo` to the connected peer.
///
/// **Catches:** the shipped wiring, which handed `CapsuleWarmer::new` the node's DISCOVERY locator.
/// That locator excludes the pool by design (a redirect must name announced holders, not every
/// connected peer), so on a relayed or partitioned network the warm located zero providers and the
/// pull failed before it dialled anything — while the holder sat in this node's own pool. It is the
/// same gap `PoolProviderLocator` was written for on the resource path, left open on the module one.
///
/// **Fixture design:** ONE actor varies. The DHT is empty in both this test and its self-exclusion
/// twin below; the only difference is whether the pool entry is a stranger or this node itself.
#[tokio::test]
async fn a_warm_reaches_a_holder_that_only_the_connected_pool_can_name() {
    let dir = temp_dir("reachability");
    let holder = mock_peer_hex(9);
    let content = node_with_pool_peer(&holder, Some(mock_peer_hex(1)));
    let transport = Arc::new(RecordingModuleTransport::default());
    let warmer = warmer_over(&content, Arc::clone(&transport), &dir);

    warmer.warm(&hex32(STORE), &hex32(ROOT)).await;

    // The assertion is on the SET of peers asked, not on the sequence. Both halves of the property
    // survive that: a pull that asked NOBODY leaves the set empty, and a pull that reached past the
    // pool puts a second id in it. What the set deliberately does NOT pin is HOW MANY TIMES the
    // holder was asked, because that is dig-download's retry budget and not this test's subject --
    // 0.19.2 added an across-round descriptor re-ask (dig-download#37), so this holder, which never
    // answers, is now asked `MAX_DESCRIPTOR_ATTEMPTS` times. Pinning the count made a legitimate
    // downstream retry fix look like a locator regression here.
    let asked: std::collections::BTreeSet<String> = transport.asked().into_iter().collect();
    assert_eq!(
        asked,
        std::collections::BTreeSet::from([holder]),
        "the connected pool peer is the ONLY candidate the DHT could not name, so a pull that \
         asked it proves the warm locator unioned the pool - and a pull that asked nobody is the \
         shipped defect"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **Proves:** the self-exclusion wraps the UNION, so a pool entry carrying THIS node's own identity
/// is never offered as a dial candidate.
///
/// **Catches:** the outer-union mistake — `UnionLocator::new([pool, SelfExcluding(discovery)])`
/// instead of `SelfExcluding(UnionLocator::new([pool, discovery]))`. The test above passes under
/// BOTH nestings, because a stranger in the pool is offered either way; only a self entry can tell
/// them apart. A relay-introduced self-connection genuinely puts this node in its own pool
/// (`NodeContent::new` records the run that found it), and the resulting self-dial starves the
/// pull's confirm round while a reachable holder is connected.
///
/// **Fixture design:** identical to the test above in every respect except the pool entry's
/// `peer_id`, which is this node's own. Asserting zero calls without that twin would be vacuous —
/// a warm that never located anything at all also asks nobody.
#[tokio::test]
async fn a_pool_entry_naming_this_node_is_never_a_dial_candidate() {
    let dir = temp_dir("self-exclusion");
    let me = mock_peer_hex(9);
    let content = node_with_pool_peer(&me, Some(me.clone()));
    let transport = Arc::new(RecordingModuleTransport::default());
    let warmer = warmer_over(&content, Arc::clone(&transport), &dir);

    warmer.warm(&hex32(STORE), &hex32(ROOT)).await;

    assert!(
        transport.asked().is_empty(),
        "this node offered ITSELF as a holder of a capsule it does not have; the self-exclusion \
         must wrap the union, not sit inside it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **Proves:** the two locators are DIFFERENT CLASSES — the discovery locator still names nobody for
/// a merely-connected peer, while the warm locator names it.
///
/// This is the executable form of `PoolProviderLocator`'s module rule: the pool is unioned into
/// LOCAL dial-candidate selection only, never into the source that feeds `find_providers` and the
/// redirect-on-miss hint, because *a redirect must name genuine announced holders, not every
/// connected peer*. Unioning the pool into discovery would launder reachability into holdership
/// across the network, in an answer this node SENDS to another node.
///
/// **Catches:** a future lane closing a redirect miss by adding the pool to `self.locator` — which
/// would make both halves of this assertion name the peer, and would be invisible to the two tests
/// above because both would still pass.
#[tokio::test]
async fn discovery_still_excludes_the_pool_that_the_warm_locator_includes() {
    let peer = mock_peer_hex(9);
    let content = node_with_pool_peer(&peer, Some(mock_peer_hex(1)));
    let capsule = dig_dht::ContentId::capsule(STORE, ROOT);

    let discovered = content
        .discovery_locator()
        .find_providers(&capsule)
        .await
        .expect("an empty DHT answers, it does not fail");
    let warm = content
        .warm_provider_locator()
        .find_providers(&capsule)
        .await
        .expect("the warm locator answers");

    assert!(
        discovered.is_empty(),
        "a merely-CONNECTED peer is not an announced holder, and the discovery locator is what \
         this node TELLS other nodes; naming it there launders reachability into holdership"
    );
    assert_eq!(
        warm.iter()
            .map(|record| record.provider_peer_id.as_str())
            .collect::<Vec<_>>(),
        vec![peer.as_str()],
        "the warm locator selects LOCAL dial candidates and its output never leaves this node, so \
         the connected peer belongs in it"
    );
}
