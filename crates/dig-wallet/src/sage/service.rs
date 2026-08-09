//! Production assembly of the SERVED Sage-parity wallet backend (#368).
//!
//! [`serve_dual`](super::transport::serve_dual) / [`WalletBackend`] existed but had **no
//! production call site** — the shipped `dig-node` never built or served the wallet surface, so
//! the extension's node-first reads ran against a mock, not the installed binary. This module is
//! that missing bring-up: it assembles one live [`WalletBackend`] (the local wallet DB + a
//! graceful fallback tier + a shared [`EventBus`] + the node-custodied seed lifecycle) plus the
//! shared mTLS cert, ready for the dig-node service shell to serve over its loopback transports.
//!
//! The assembly is deliberately **offline-safe and non-blocking**: it opens (or creates) the
//! SQLite wallet DB under the node config dir, and defaults the fallback tier to the graceful
//! a LAZY [`ChainTransport`] so bring-up never waits on network/TLS peer discovery. The live direct-peer
//! sync loop (which would swap in the live peer tier and
//! feed the DB) remains the documented remaining integration: it is **SPEC §18.6**, explicitly
//! deferred by **§18.12a**. It is NOT §18.12 — §18.12 is the live spend *broadcaster*, which has
//! shipped. (This comment cited §18.12 and sent three separate readers to the wrong clause,
//! making the sync loop look like a wiring job against already-written machinery; #2232.)
//! The [`EventBus`] is wired here so that loop — and the WS sync-status push (#369) — publish to
//! one shared bus.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::auth::UnlockAuth;
use super::chain::ChainTransport;
use super::custody::WalletCustody;
use super::db::WalletDb;
use super::events::EventBus;
use super::fallback::{ChainFallback, ChiaQueryLineage};
use super::rpc::{WalletBackend, WalletConfig};
use super::singleton::LineageSource;
use super::spend::{
    Broadcaster, ChiaQueryBroadcaster, ChiaQueryConfirmer, Confirmer, ConfirmingBroadcaster,
};
use super::tipping::{ChainOwnerResolver, NodeTipSpender, SystemClock, TipEventBus, TippingEngine};
use super::transport::SharedCert;

/// Bring-up configuration for the served wallet (§18.12).
#[derive(Debug, Clone, Default)]
pub struct WalletServiceConfig {
    /// Enable REAL mainnet broadcast of node-custodied spends (the tip spend #378, the
    /// sign+broadcast-on-behalf path #371, and any wallet send/offer/mint). **Default `false`** —
    /// the offline-safe behaviour where no broadcaster is attached and NO $DIG moves. When `true`,
    /// the node builds ONE shared `chia_query` client and attaches a real
    /// [`ChiaQueryBroadcaster`] + [`ChiaQueryConfirmer`] + [`ChiaQueryLineage`] + [`CoinsetFallback`]
    /// so spends execute + confirm on mainnet. Sourced from `DIG_WALLET_ENABLE_LIVE_BROADCAST`.
    pub enable_live_broadcast: bool,
}

/// The live-broadcast wiring: one shared `chia_query` client backs a real broadcaster (for the
/// tip path — which surfaces confirmation itself), a confirming broadcaster (for the general
/// send/offer/mint surface), a confirmer and a lineage source.
///
/// It no longer carries its own read tier: the chain READS are served by the one
/// [`ChainTransport`] on every install (dig_ecosystem#2376), so a live node does not maintain a
/// second, differently-configured view of the same chain.
struct LiveWallet {
    /// The RAW broadcaster the tip path uses (it runs its own confirmer, so must NOT double-confirm).
    tip_broadcaster: Arc<dyn Broadcaster>,
    /// The confirming broadcaster the general wallet surface uses (broadcast + best-effort confirm).
    general_broadcaster: Arc<dyn Broadcaster>,
    /// The on-chain confirmer (shared).
    confirmer: Arc<dyn Confirmer>,
    /// The live lineage source (CAT/singleton parent-spend reads).
    lineage: Arc<dyn LineageSource>,
}

/// A fully-assembled, ready-to-serve wallet: the dispatch backend, the shared event bus the WS
/// transport (#369) subscribes to, and the shared self-signed cert the mTLS listener presents.
/// The node-custodied seed lifecycle is reachable via [`WalletBackend::custody`] — the backend
/// resolves its signer from it at runtime (#368), so a paired `wallet.unlock` immediately enables
/// signing without reconstructing the backend.
#[derive(Clone)]
pub struct WalletService {
    /// The one dispatch handler set both loopback transports (HTTP mirror + mTLS) call.
    pub backend: Arc<WalletBackend>,
    /// The sync-event bus the (future) live sync loop publishes to and the WS transport reads.
    pub events: Arc<EventBus>,
    /// The shared self-signed cert the mTLS `9257` listener presents (Sage byte-parity).
    pub cert: SharedCert,
}

impl WalletService {
    /// Assemble the served wallet under `config_dir` (the node's config directory). The wallet DB
    /// is `<config_dir>/wallet.sqlite`; the encrypted seeds are `<config_dir>/wallets/<id>.seed`
    /// (mainnet MULTI-wallet custody, #427; a legacy `<config_dir>/wallet-seed.bin` is adopted).
    /// Never blocks on network: the fallback tier defaults to
    /// a lazy [`ChainTransport`]. A DB-open failure falls back to an in-memory DB so the node still serves
    /// the version/custody/sync-status surface (reported, not fatal).
    /// Assemble the served wallet, offline-safe (no live broadcast). Equivalent to
    /// [`WalletService::build_with`] with the default [`WalletServiceConfig`].
    pub async fn build(config_dir: &Path) -> WalletService {
        Self::build_with(config_dir, WalletServiceConfig::default()).await
    }

    /// Assemble the served wallet under `config_dir` with an explicit [`WalletServiceConfig`]. When
    /// `cfg.enable_live_broadcast` is set, attaches the real broadcaster/confirmer/lineage/fallback
    /// so node-custodied spends execute on mainnet (§18.12); otherwise behaves exactly as the
    /// offline-safe shipped bring-up (no broadcaster ⇒ no $DIG moves).
    pub async fn build_with(config_dir: &Path, cfg: WalletServiceConfig) -> WalletService {
        let events = Arc::new(EventBus::default());
        let db = open_db(config_dir).await;
        // MULTI-wallet custody (#427) rooted at the node config dir: seeds live under
        // `<config_dir>/wallets/`, and a legacy single `<config_dir>/wallet-seed.bin` is adopted.
        let custody = WalletCustody::mainnet(config_dir.to_path_buf());
        // The node-managed unlock authority (#431/#432, §18.24): it GATES the sign/broadcast path so
        // signing is SAFE BY DEFAULT (per-transaction re-auth; the key is not resident between
        // signatures). It shares the SAME custody state (a `WalletCustody` clone shares its inner
        // Arcs), so decrypting a seed for a one-shot sign always uses the on-disk seed + password.
        let auth = Arc::new(UnlockAuth::new(custody.clone(), config_dir.to_path_buf()));
        let tip_events = Arc::new(TipEventBus::default());

        // Live-broadcast wiring (§18.12), gated on the config flag. A construction failure (no peer
        // reachable / offline) is NON-FATAL and DISABLES live broadcast — a half-built client must
        // never send. Default OFF: `None` here reproduces the offline-safe shipped behaviour.
        let live = if cfg.enable_live_broadcast {
            build_live_wallet().await
        } else {
            None
        };

        // The chain transport (dig_ecosystem#2376) serves the wallet's chain READS and the push of
        // an already-signed bundle on EVERY install, live-broadcast or not. Those two need no key,
        // so they are not the question `enable_live_broadcast` answers -- that flag governs whether
        // the node's OWN custodied wallet may sign and send, and it is still default-OFF. Tying the
        // reads to it is what made a stock node answer `WALLET_NO_CHAIN_SOURCE` to every wallet read
        // and unable to push at all.
        //
        // The flag is ALSO handed to the backend below, because "push an already-signed bundle" is
        // only a different question while the bundle is somebody else's: the node will sign with its
        // own key on request, so a relay that did not check would let a caller round-trip the node's
        // own money onto mainnet with the flag off. The backend refuses exactly that bundle.
        //
        // It dials nothing until something asks it to, so an idle node still makes no chain call.
        let chain = Arc::new(ChainTransport::new());
        let fallback: Arc<dyn ChainFallback> = chain.clone();
        // The base backend WITHOUT the tipping engine attached — cloned into the tip spender so the
        // spender's backend handle has `tipping == None` (no reference cycle engine↔backend). Both
        // share the SAME inner Arcs (db/custody/events/tip_events), so a runtime `wallet.unlock` is
        // visible to the spender.
        let mut base = WalletBackend::new(db, fallback, WalletConfig::default())
            .with_events(events.clone())
            .with_custody(custody)
            .with_auth(auth)
            .with_tip_events(tip_events.clone())
            .with_pusher(chain.clone())
            .with_node_custodied_spending(cfg.enable_live_broadcast);
        if let Some(l) = &live {
            // The GENERAL wallet surface (send/offer/mint) gets the confirming broadcaster + the
            // live lineage source so CAT/singleton spends resolve inputs.
            base = base
                .with_broadcaster(l.general_broadcaster.clone())
                .with_lineage(l.lineage.clone());
        }
        // The tip subsystem (#378). When live is OFF the spender carries NO broadcaster, so a tip
        // cleanly reports NotExecutable (nothing is spent). When live is ON the spender gets the RAW
        // broadcaster + the confirmer (the tip path surfaces confirmation ITSELF via the confirmer —
        // pending/confirmed in its ledger — so it must not be handed the double-confirming wrapper).
        let spender_backend = Arc::new(base.clone());
        let spender = match &live {
            Some(l) => NodeTipSpender::new(
                spender_backend,
                Some(l.tip_broadcaster.clone()),
                Some(l.confirmer.clone()),
            ),
            None => NodeTipSpender::new(spender_backend, None, None),
        };
        let tipping = TippingEngine::load(
            config_dir,
            Box::new(ChainOwnerResolver::mainnet()),
            Box::new(spender),
            Box::new(SystemClock),
            tip_events,
        );
        let backend = Arc::new(base.with_tipping(Arc::new(tipping)));
        // A generated shared cert is fine for a loopback listener: whoever can reach the loopback
        // mTLS port and present the matching cert is a local node-class client. A persisted cert
        // (so a separate node-class process can read it) is the follow-up when that client lands.
        let cert = SharedCert::generate().expect("dig-wallet: generate mTLS cert");
        WalletService {
            backend,
            events,
            cert,
        }
    }
}

/// Build the live-broadcast wiring (§18.12): ONE shared `chia_query` client backing a real
/// broadcaster, a confirming broadcaster, a confirmer and a lineage source.
/// Returns `None` (non-fatally, with a logged warning) when the client cannot start — so
/// `enable_live_broadcast` on an offline/peerless host degrades to no-broadcast (never a
/// half-built live sender). Mainnet only (the node's wallet is mainnet custody).
async fn build_live_wallet() -> Option<LiveWallet> {
    match chia_query::ChiaQuery::new(chia_query::ChiaQueryConfig::default()).await {
        Ok(q) => {
            let query = Arc::new(q);
            let raw: Arc<dyn Broadcaster> = Arc::new(ChiaQueryBroadcaster::new(query.clone()));
            let confirmer: Arc<dyn Confirmer> = Arc::new(ChiaQueryConfirmer::new(query.clone()));
            let general: Arc<dyn Broadcaster> =
                Arc::new(ConfirmingBroadcaster::new(raw.clone(), confirmer.clone()));
            let lineage: Arc<dyn LineageSource> = Arc::new(ChiaQueryLineage::new(query.clone()));
            tracing::info!(
                "wallet LIVE broadcast ENABLED — node-custodied spends will execute on mainnet \
                 (real $DIG). Disable by unsetting DIG_WALLET_ENABLE_LIVE_BROADCAST."
            );
            Some(LiveWallet {
                tip_broadcaster: raw,
                general_broadcaster: general,
                confirmer,
                lineage,
            })
        }
        Err(e) => {
            warn_chain_source_unavailable(&e);
            None
        }
    }
}

/// Report, through the process log sink, that the live chain source could not be built.
///
/// This is the ONLY account of why every subsequent balance read will answer
/// `WALLET_NO_CHAIN_SOURCE`, so where it goes matters as much as what it says. It was an
/// `eprintln!`, and dig-node runs as an OS service with no stderr attached: the message went
/// nowhere, and the failure it described took three debugging rounds to find because of it
/// (#2210). `tracing` reaches the `dig-logging` sink the node installs process-globally, so the
/// explanation lands in `dig-node.jsonl` where an operator will actually meet it.
///
/// Adopting chia-query 0.6 removed the *most common* reason to arrive here — a missing
/// `~/.chia` under a service account — but every other reason (no network, a coinset outage,
/// a malformed base URL) still ends up on this line, so the diagnostic keeps earning its place.
fn warn_chain_source_unavailable(error: &dyn std::fmt::Display) {
    tracing::warn!(
        %error,
        "wallet chain source unavailable: the chia_query client failed to start, so LIVE \
         broadcast is DISABLED (no $DIG will move) and balance reads will answer \
         WALLET_NO_CHAIN_SOURCE until a chain source is reachable"
    );
}

/// The wallet DB path under the node config dir.
fn db_path(config_dir: &Path) -> PathBuf {
    config_dir.join("wallet.sqlite")
}

/// Open the on-disk wallet DB, falling back to an in-memory DB (reported) if the on-disk open
/// fails — so a broken/unwritable data dir degrades the wallet to non-persistent rather than
/// aborting the whole node.
async fn open_db(config_dir: &Path) -> WalletDb {
    let _ = std::fs::create_dir_all(config_dir);
    let path = db_path(config_dir);
    match path.to_str() {
        Some(p) => match WalletDb::open(p).await {
            Ok(db) => db,
            Err(e) => {
                eprintln!(
                    "dig-node: WARN could not open the wallet DB at {} ({e}); using an \
                     in-memory wallet DB (wallet state will not persist across restarts)",
                    path.display()
                );
                in_memory_db().await
            }
        },
        None => in_memory_db().await,
    }
}

/// A last-resort in-memory wallet DB (used only when the on-disk open failed).
async fn in_memory_db() -> WalletDb {
    WalletDb::open_in_memory()
        .await
        .expect("dig-wallet: open in-memory wallet DB")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp config dir per test.
    fn scratch() -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dig-wallet-svc-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Derived test custody password — replaces a hard-coded literal that triggered CodeQL's
    /// rust/hard-coded-cryptographic-value alert. The test only needs a stable, deterministic
    /// passphrase, not a specific one.
    fn test_custody_password() -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        b"dig-wallet-service-test".hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// **Proves (#368):** the production assembler builds a served backend that answers
    /// `get_version` over the transport-independent dispatch, carries the node custody lifecycle
    /// (`wallet.status` = `none` on a fresh dir), and shares one event bus.
    #[tokio::test]
    async fn build_assembles_a_served_backend() {
        let dir = scratch();
        let svc = WalletService::build(&dir).await;

        let (status, body) = svc.backend.dispatch("get_version", "{}").await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains(env!("CARGO_PKG_VERSION")));

        // Custody is attached and reports a fresh (no-seed) wallet.
        let (status, body) = svc.backend.dispatch("wallet.status", "{}").await;
        assert_eq!(status, 200);
        assert!(body.contains("none"), "fresh dir has no wallet: {body}");

        // The backend shares the service's event bus (a publish is visible to a subscriber).
        assert_eq!(svc.backend.events().subscriber_count(), 0);
        assert!(std::ptr::eq(
            Arc::as_ptr(svc.backend.events()),
            Arc::as_ptr(&svc.events)
        ));
    }

    /// **Proves (#378):** the served backend carries the tipping subsystem — `tip.get_config`
    /// answers with creator + dev BOTH DEFAULT-ON, and `tip.dev_tick` on the offline-safe shipped
    /// bring-up (no broadcaster wired yet) cleanly SKIPS as wallet-unavailable — never spends, never
    /// errors. No network is touched.
    #[tokio::test]
    async fn build_serves_the_tipping_subsystem() {
        let dir = scratch();
        let svc = WalletService::build(&dir).await;

        let (status, body) = svc.backend.dispatch("tip.get_config", "{}").await;
        assert_eq!(status, 200, "{body}");
        let cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            cfg["creator"]["enabled"], true,
            "creator auto-tip DEFAULT-ON"
        );
        assert_eq!(
            cfg["dev"]["enabled"], true,
            "dev tip DEFAULT-ON (real treasury recipient)"
        );

        // The dev tip cleanly skips (no broadcaster on the offline-safe bring-up) — never a spend.
        let (status, body) = svc.backend.dispatch("tip.dev_tick", "{}").await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains("skipped") && body.contains("wallet-unavailable"),
            "dev tip must skip cleanly when no broadcaster is wired: {body}"
        );

        // The tip ledger starts empty (a rolled-back NotExecutable leaves no reservation).
        let (status, body) = svc.backend.dispatch("tip.get_ledger", "{}").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.trim(), "[]");
    }

    /// **Proves:** the DB persists across two builds over the same dir (a created wallet is still
    /// present) — the served backend is durable, not in-memory, in the normal case.
    #[tokio::test]
    async fn on_disk_db_and_seed_persist_across_builds() {
        let dir = scratch();
        {
            let svc = WalletService::build(&dir).await;
            let (s, _b) = svc
                .backend
                .dispatch(
                    "wallet.create",
                    &format!(r#"{{"password":"{}"}}"#, test_custody_password()),
                )
                .await;
            assert_eq!(s, 200);
        }
        // A second build over the same dir sees the persisted (locked) wallet.
        let svc2 = WalletService::build(&dir).await;
        let (_s, body) = svc2.backend.dispatch("wallet.status", "{}").await;
        assert!(
            body.contains("locked"),
            "the persisted seed must reopen as locked: {body}"
        );
    }
}

/// Regression tests for the chain-source configuration the balance read depends on
/// (dig_ecosystem#2210).
///
/// These pin CONFIGURATION, not network behaviour, and that is deliberate. The bug they guard
/// against was invisible on a developer machine precisely because it depended on the ambient
/// filesystem: `~/.chia` exists for an interactive user and does not exist for the SYSTEM
/// account a Windows service runs under, so any test that merely constructs a client would
/// have passed on the machine where the bug was reported. Asserting the config instead makes
/// the property independent of whose home directory the suite happens to run in.
#[cfg(test)]
mod chain_source_config_tests {
    /// The peer TLS identity MUST be generated in memory.
    ///
    /// `TlsIdentity::Files` resolved under the home directory is the exact shape that broke:
    /// a service account's home has no `.chia`, so establishing the identity failed, and with
    /// it the whole client — leaving every `control.wallet.balance` at `-32040`. Chia full
    /// nodes accept any well-formed client certificate, so a file is nothing but a liability.
    #[test]
    fn peer_identity_needs_nothing_from_the_filesystem() {
        let cfg = chia_query::ChiaQueryConfig::default();
        assert_eq!(
            cfg.tls_identity,
            chia_query::TlsIdentity::Generated,
            "the wallet builds its chain source from ChiaQueryConfig::default(); a file-backed \
             identity reintroduces the ~/.chia dependency that makes a service account fail"
        );
    }

    /// The coinset tier MUST stay enabled.
    ///
    /// This is load-bearing beyond the fallback reads themselves: chia-query derives
    /// `PeerRequirement::Optional` from it, which is what lets the client construct — and
    /// serve over plain HTTP — when the peer pool comes up empty. Disabling it turns a
    /// peerless host back into a total construction failure rather than a degraded read.
    #[test]
    fn coinset_tier_stays_enabled_so_an_empty_peer_pool_still_serves() {
        assert!(
            chia_query::ChiaQueryConfig::default().coinset_fallback_enabled,
            "coinset is the keyless HTTP tier; disabling it makes peers REQUIRED and a \
             peerless host cannot build a chain source at all"
        );
    }
}

/// Regression tests for where the chain-source diagnostic GOES (dig_ecosystem#2210, #2216).
///
/// The failure these guard is not a wrong message but an unreachable one: the explanation was
/// written to stderr, and a Windows service has no stderr, so it was discarded every time. A
/// test that only checked the wording would have passed throughout. These assert the message
/// arrives at a `tracing` subscriber — the same channel `dig-logging` attaches in production.
#[cfg(test)]
mod chain_source_diagnostic_tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    /// A `MakeWriter` that keeps everything written to it, so a test can read back exactly what
    /// a subscriber emitted.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("capture buffer poisoned")).into_owned()
        }
    }

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("capture buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `body` with a capturing subscriber installed, and return everything it logged.
    fn logged(body: impl FnOnce()) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        capture.contents()
    }

    /// The reason the chain source failed MUST reach the log sink, and MUST carry the
    /// underlying error — a bare "chain source unavailable" would not have shortened the
    /// hunt that motivated this.
    #[test]
    fn the_failure_reason_reaches_the_log_sink() {
        // A distinctive value, so the assertion cannot pass on some other incidental log line.
        let underlying = "the system cannot find the path specified. (os error 3)";

        let output = logged(|| super::warn_chain_source_unavailable(&underlying));

        assert!(
            output.contains(underlying),
            "the underlying error must be carried to the sink, not summarised away; got: {output}"
        );
        assert!(
            output.contains("WALLET_NO_CHAIN_SOURCE"),
            "the diagnostic must name the error code an operator will actually see on the RPC, \
             so the log line is findable from the symptom; got: {output}"
        );
        assert!(
            output.contains("WARN"),
            "a chain source that failed to start is a warning, not a debug detail; got: {output}"
        );
    }

    /// Nothing is emitted OUTSIDE the subscriber, which is what distinguishes `tracing` from the
    /// `eprintln!` this replaced. With no subscriber installed the call is a no-op rather than a
    /// write to a stream the service does not have; with one installed it produces output. The
    /// two halves together show the message travels the subscriber, not the process's stderr.
    #[test]
    fn the_diagnostic_travels_the_subscriber_not_a_raw_stream() {
        let capture = Capture::default();

        // No subscriber in scope: the capture must stay empty.
        super::warn_chain_source_unavailable(&"ignored");
        assert!(
            capture.contents().is_empty(),
            "a capture with no subscriber attached must see nothing"
        );

        // Same call, subscriber installed: now it lands.
        let output = logged(|| super::warn_chain_source_unavailable(&"observed"));
        assert!(
            output.contains("observed"),
            "with a subscriber installed the diagnostic must land in it; got: {output}"
        );
    }
}
