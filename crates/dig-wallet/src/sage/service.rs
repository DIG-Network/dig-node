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
//! [`EmptyFallback`] so bring-up never waits on network/TLS peer discovery. The live direct-peer
//! sync loop (which would swap in the [`CoinsetFallback`](super::fallback::CoinsetFallback) and
//! feed the DB) remains the documented remaining integration (SPEC §18.12); the [`EventBus`] is
//! wired here so that loop — and the WS sync-status push (#369) — publish to one shared bus.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::custody::WalletCustody;
use super::db::WalletDb;
use super::events::EventBus;
use super::fallback::{ChainFallback, ChiaQueryLineage, CoinsetFallback, EmptyFallback};
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
/// send/offer/mint surface), a confirmer, a lineage source, and a coinset fallback read tier.
struct LiveWallet {
    /// The RAW broadcaster the tip path uses (it runs its own confirmer, so must NOT double-confirm).
    tip_broadcaster: Arc<dyn Broadcaster>,
    /// The confirming broadcaster the general wallet surface uses (broadcast + best-effort confirm).
    general_broadcaster: Arc<dyn Broadcaster>,
    /// The on-chain confirmer (shared).
    confirmer: Arc<dyn Confirmer>,
    /// The live lineage source (CAT/singleton parent-spend reads).
    lineage: Arc<dyn LineageSource>,
    /// The coinset/peer fallback read tier.
    fallback: Arc<dyn ChainFallback>,
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
    /// is `<config_dir>/wallet.sqlite`; the encrypted seed is `<config_dir>/wallet-seed.bin`
    /// (mainnet custody). Never blocks on network: the fallback tier defaults to
    /// [`EmptyFallback`]. A DB-open failure falls back to an in-memory DB so the node still serves
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
        let custody = WalletCustody::mainnet(seed_path(config_dir));
        let tip_events = Arc::new(TipEventBus::default());

        // Live-broadcast wiring (§18.12), gated on the config flag. A construction failure (no peer
        // reachable / offline) is NON-FATAL and DISABLES live broadcast — a half-built client must
        // never send. Default OFF: `None` here reproduces the offline-safe shipped behaviour.
        let live = if cfg.enable_live_broadcast {
            build_live_wallet().await
        } else {
            None
        };

        let fallback: Arc<dyn ChainFallback> = match &live {
            Some(l) => l.fallback.clone(),
            None => Arc::new(EmptyFallback),
        };
        // The base backend WITHOUT the tipping engine attached — cloned into the tip spender so the
        // spender's backend handle has `tipping == None` (no reference cycle engine↔backend). Both
        // share the SAME inner Arcs (db/custody/events/tip_events), so a runtime `wallet.unlock` is
        // visible to the spender.
        let mut base = WalletBackend::new(db, fallback, WalletConfig::default())
            .with_events(events.clone())
            .with_custody(custody)
            .with_tip_events(tip_events.clone());
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
/// broadcaster, a confirming broadcaster, a confirmer, a lineage source, and a coinset fallback.
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
            let fallback: Arc<dyn ChainFallback> = Arc::new(CoinsetFallback::new(query.clone()));
            eprintln!(
                "dig-node: wallet LIVE broadcast ENABLED — node-custodied spends will execute on \
                 mainnet (real $DIG). Disable by unsetting DIG_WALLET_ENABLE_LIVE_BROADCAST."
            );
            Some(LiveWallet {
                tip_broadcaster: raw,
                general_broadcaster: general,
                confirmer,
                lineage,
                fallback,
            })
        }
        Err(e) => {
            eprintln!(
                "dig-node: WARN DIG_WALLET_ENABLE_LIVE_BROADCAST is set but the chia_query client \
                 failed to start ({e}); LIVE broadcast DISABLED (no $DIG will move) — the wallet \
                 stays offline-safe until a node/network is reachable"
            );
            None
        }
    }
}

/// The wallet DB path under the node config dir.
fn db_path(config_dir: &Path) -> PathBuf {
    config_dir.join("wallet.sqlite")
}

/// The encrypted-seed path under the node config dir.
fn seed_path(config_dir: &Path) -> PathBuf {
    config_dir.join("wallet-seed.bin")
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
                .dispatch("wallet.create", r#"{"password":"hunter2pw"}"#)
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
