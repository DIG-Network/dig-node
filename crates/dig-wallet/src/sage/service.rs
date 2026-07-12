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
use super::fallback::EmptyFallback;
use super::rpc::{WalletBackend, WalletConfig};
use super::tipping::{ChainOwnerResolver, NodeTipSpender, SystemClock, TipEventBus, TippingEngine};
use super::transport::SharedCert;

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
    pub async fn build(config_dir: &Path) -> WalletService {
        let events = Arc::new(EventBus::default());
        let db = open_db(config_dir).await;
        let custody = WalletCustody::mainnet(seed_path(config_dir));
        let tip_events = Arc::new(TipEventBus::default());
        // The base backend WITHOUT the tipping engine attached — cloned into the tip spender so the
        // spender's backend handle has `tipping == None` (no reference cycle engine↔backend). Both
        // share the SAME inner Arcs (db/custody/events/tip_events), so a runtime `wallet.unlock` is
        // visible to the spender.
        let base = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_events(events.clone())
            .with_custody(custody)
            .with_tip_events(tip_events.clone());
        // The tip subsystem (#378). Offline-safe: the owner resolver is a lazy coinset.org client
        // (no network at construction), and the spender carries NO broadcaster yet — so on the
        // shipped node a tip cleanly reports NotExecutable (nothing is spent) until the wallet
        // spend path's live sync/lineage/broadcaster lands (SPEC §18.12). The config/ledger/RPC/WS
        // surface is fully live now for the extension (#379/#380) to build against.
        let spender = NodeTipSpender::new(Arc::new(base.clone()), None);
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
