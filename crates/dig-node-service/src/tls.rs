//! Local HTTPS TLS wiring for `https://dig.local` (#624, the #620 local-HTTPS epic).
//!
//! dig-node serves the SAME local content surface as the plaintext `/s/` path over TLS on
//! `127.0.0.2:443`, using a leaf issued by the per-machine, name-constrained CA that the
//! `dig-cert` crate owns (#622). The CA + leaf are provisioned by the installer (#623): this
//! module NEVER generates the CA and NEVER auto-rotates the trust anchor — it only READS the
//! leaf to serve, and drives `dig-cert`'s renewal manager to keep the *leaf* fresh.
//!
//! Two responsibilities:
//!
//! - [`load_https_material`] — build the reloadable `rustls` config from the on-disk leaf,
//!   **failing SOFT** (returning `None` + logging) when no CA/leaf is present yet, so a node
//!   on a machine the installer has not provisioned simply keeps serving plaintext.
//! - [`spawn_leaf_rotation`] — run `dig-cert`'s [`RenewalManager`] at startup and daily so the
//!   leaf is re-issued from `ca.key` before it lapses and the running listener hot-reloads the
//!   new leaf with no downtime and no dropped connections.

use std::sync::Arc;
use std::time::Duration;

use dig_cert::{load_server_config, ReloadableCertResolver, RenewalManager, TlsPaths};
use rustls::ServerConfig;
use time::OffsetDateTime;

/// How often dig-node runs a leaf-renewal maintenance pass (dig-cert SPEC §6): once daily.
/// A 90-day leaf renewed at 30 days remaining leaves ample margin for the manager's own
/// bounded retry backoff, so a daily cadence never lets a leaf lapse.
const RENEWAL_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The material needed to bring up the local HTTPS listener: the `rustls` server config
/// (its cert resolver is hot-reloadable) plus the resolver handle and the TLS paths the
/// renewal manager needs.
pub struct HttpsMaterial {
    /// The `rustls::ServerConfig` to hand to the TLS listener. Its certificate resolver is
    /// the shared [`ReloadableCertResolver`], so a leaf rotation is picked up live.
    pub config: ServerConfig,
    /// The resolver handle the renewal manager fires `reload()` on after a rotation.
    pub resolver: Arc<ReloadableCertResolver>,
    /// The canonical TLS paths (`ca.{key,crt}`, `leaf.{key,crt}`) the renewal manager reads.
    pub paths: TlsPaths,
}

/// Try to load the dig-cert leaf backing `https://dig.local` from `paths`.
///
/// **Fail-soft (SPEC #624):** returns `None` — and logs why — when the leaf is absent or
/// unreadable, because the installer (#623) is what provisions the CA + leaf. Until then the
/// node serves plaintext only; HTTPS is never a hard requirement. A present-but-unparseable
/// leaf is likewise treated as "not yet available" rather than a fatal error.
pub fn load_https_material(paths: TlsPaths) -> Option<HttpsMaterial> {
    // Gate on BOTH files existing before touching rustls — the common "installer hasn't run
    // yet" case, reported as an informational line (not a warning), since it is expected.
    if !paths.leaf_cert().exists() || !paths.leaf_key().exists() {
        eprintln!(
            "dig-node: HTTPS (https://dig.local) unavailable — no TLS leaf under {} yet. \
             The installer provisions the per-machine CA + leaf (#623); serving plaintext only.",
            paths.root.display()
        );
        return None;
    }
    match load_server_config(paths.leaf_cert(), paths.leaf_key()) {
        Ok((config, resolver)) => Some(HttpsMaterial {
            config,
            resolver,
            paths,
        }),
        Err(e) => {
            eprintln!(
                "dig-node: WARN could not load the TLS leaf under {} ({e}); serving plaintext \
                 only. HTTPS starts once a valid CA + leaf are present (#623).",
                paths.root.display()
            );
            None
        }
    }
}

/// Spawn the leaf-rotation loop (dig-cert [`RenewalManager`], SPEC §6). Runs a maintenance
/// pass immediately at startup and once every [`RENEWAL_INTERVAL`] thereafter. Each pass:
/// re-issues the leaf from `ca.key` when it is within 30 days of expiry, atomically swaps
/// `leaf.{key,crt}` (temp + rename, so no reader sees a torn or mismatched pair), and fires
/// `resolver.reload()` so the running HTTPS listener presents the new leaf WITHOUT a restart.
///
/// dig-node is the runtime rotation OWNER but delegates the HOW to dig-cert's manager, whose
/// resolver reload reads the completed pair (and keeps the previous cert on a torn read), so
/// the listener never serves an expired or mismatched leaf. The CA trust anchor is NEVER
/// auto-rotated here: an approaching CA expiry is only REPORTED (`ca_renewal_due`); anchor
/// rotation is an explicit, installer-coordinated `dig-cert rotate_ca` (SPEC §6.4).
pub fn spawn_leaf_rotation(paths: TlsPaths, resolver: Arc<ReloadableCertResolver>) {
    // `RenewalManager::maintain` is synchronous and may sleep on its retry backoff, so each
    // pass runs on a blocking worker — never on an async runtime thread. The manager is shared
    // (Arc) so a clone can move into each blocking task.
    let manager = Arc::new(RenewalManager::new(paths, resolver));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RENEWAL_INTERVAL);
        loop {
            // `interval`'s first tick completes immediately → the startup pass; subsequent
            // ticks are the daily cadence.
            ticker.tick().await;
            let manager = manager.clone();
            match tokio::task::spawn_blocking(move || manager.maintain(OffsetDateTime::now_utc()))
                .await
            {
                Ok(Ok(report)) => {
                    if report.leaf_renewed {
                        eprintln!(
                            "dig-node: TLS leaf for https://dig.local renewed and hot-reloaded \
                             (attempts={})",
                            report.attempts
                        );
                    }
                    if report.ca_renewal_due {
                        eprintln!(
                            "dig-node: WARN the local CA is within its renewal window. CA rotation \
                             is installer-coordinated (dig-cert rotate_ca) and re-installs trust — \
                             the node does NOT auto-rotate the anchor."
                        );
                    }
                }
                Ok(Err(e)) => eprintln!(
                    "dig-node: WARN TLS leaf renewal pass failed ({e}); HTTPS keeps serving the \
                     current leaf and the next pass retries."
                ),
                Err(e) => {
                    eprintln!("dig-node: WARN TLS leaf renewal task did not complete ({e})")
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_cert::{generate_ca, issue_leaf, ParsedCa};

    /// Write a freshly generated CA + leaf into `paths` so a test can exercise the loader.
    fn provision(paths: &TlsPaths) {
        std::fs::create_dir_all(&paths.root).unwrap();
        let now = OffsetDateTime::now_utc();
        let ca = generate_ca("test-host", now).unwrap();
        std::fs::write(paths.ca_cert(), &ca.cert_pem).unwrap();
        std::fs::write(paths.ca_key(), &ca.key_pem).unwrap();
        let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
        let leaf = issue_leaf(&parsed, now).unwrap();
        std::fs::write(paths.leaf_cert(), &leaf.cert_pem).unwrap();
        std::fs::write(paths.leaf_key(), &leaf.key_pem).unwrap();
    }

    #[test]
    fn load_is_none_when_no_leaf_present() {
        // Fail-soft: an unprovisioned machine (no installer run yet) yields no HTTPS material,
        // so the caller falls back to plaintext instead of failing to start.
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        assert!(load_https_material(paths).is_none());
    }

    #[test]
    fn load_is_some_when_leaf_present() {
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        provision(&paths);
        let material = load_https_material(paths).expect("a provisioned leaf loads");
        // Building the config proves the leaf key parsed as a usable ECDSA signing key, and the
        // resolver re-reads the just-written pair without error (the rotation hot-reload path).
        material
            .resolver
            .reload()
            .expect("reload the just-written leaf pair");
    }
}
