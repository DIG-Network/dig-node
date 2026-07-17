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
use tokio::time::{Interval, MissedTickBehavior};

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
    // Defence-in-depth (#661): refuse to touch TLS material — the leaf now, and `ca.key` later on
    // the rotation path — when the TLS root is not owned by SYSTEM/Administrators (Windows) or
    // root and not group/world-writable (unix). A user-writable root could hold an attacker-swapped
    // `ca.key`, and this service reads that key with privilege. Fail CLOSED to plaintext; the
    // installer (#623) provisions the root under a privileged owner.
    if !crate::security::dir_is_privileged(&paths.root) {
        tracing::warn!(
            tls_root = %paths.root.display(),
            "refusing HTTPS: TLS root is not privileged-owned (SYSTEM/Administrators or root) or is \
             user-writable; serving plaintext only. The installer (#623) provisions this root under \
             a privileged owner"
        );
        return None;
    }
    load_leaf_material(paths)
}

/// Load the leaf material from `paths` WITHOUT the owner gate — the fail-soft leaf-existence +
/// parse logic. Split from [`load_https_material`] so the leaf-loading behaviour stays unit-testable
/// against an ordinary tempdir, while the #661 owner gate is exercised on its own.
fn load_leaf_material(paths: TlsPaths) -> Option<HttpsMaterial> {
    // Gate on BOTH files existing before touching rustls — the common "installer hasn't run
    // yet" case, reported as an informational line (not a warning), since it is expected.
    if !paths.leaf_cert().exists() || !paths.leaf_key().exists() {
        // Expected on a machine the installer has not provisioned yet — INFO, not WARN.
        tracing::info!(
            tls_root = %paths.root.display(),
            "https://dig.local unavailable: no TLS leaf yet. The installer provisions the \
             per-machine CA + leaf (#623); serving plaintext only"
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
            tracing::warn!(
                tls_root = %paths.root.display(),
                error = %e,
                "could not load the TLS leaf; serving plaintext only. HTTPS starts once a valid \
                 CA + leaf are present (#623)"
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
        let mut ticker = new_renewal_ticker();
        loop {
            // `interval`'s first tick completes immediately → the startup pass; subsequent
            // ticks are the daily cadence.
            ticker.tick().await;
            run_rotation_pass(manager.clone(), OffsetDateTime::now_utc()).await;
        }
    });
}

/// Build the daily leaf-renewal ticker: a [`RENEWAL_INTERVAL`] interval whose missed-tick policy is
/// [`MissedTickBehavior::Delay`] (#660). The default `Burst` policy would, after the host sleeps or
/// suspends across several intervals, immediately fire one renewal pass per missed tick — a useless
/// thundering burst of identical maintenance passes. `Delay` coalesces the whole backlog into a
/// single catch-up pass and then resumes the daily cadence, which is exactly right: one pass fully
/// reconciles the leaf regardless of how many ticks were missed.
fn new_renewal_ticker() -> Interval {
    let mut ticker = tokio::time::interval(RENEWAL_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}

/// Run one leaf-renewal maintenance pass on a blocking worker (the synchronous manager may sleep on
/// its retry backoff) and log the outcome. Split from the loop so the pass — the renewal action and
/// its logging — is unit-testable against a real [`RenewalManager`] without waiting a day for a tick.
async fn run_rotation_pass(manager: Arc<RenewalManager>, now: OffsetDateTime) {
    match tokio::task::spawn_blocking(move || manager.maintain(now)).await {
        Ok(Ok(report)) => {
            if report.leaf_renewed {
                tracing::info!(
                    attempts = report.attempts,
                    "TLS leaf for https://dig.local renewed and hot-reloaded"
                );
            }
            if report.ca_renewal_due {
                tracing::warn!(
                    "the local CA is within its renewal window. CA rotation is \
                     installer-coordinated (dig-cert rotate_ca) and re-installs trust — the node \
                     does NOT auto-rotate the anchor"
                );
            }
        }
        Ok(Err(e)) => tracing::warn!(
            error = %e,
            "TLS leaf renewal pass failed; HTTPS keeps serving the current leaf and the next pass \
             retries"
        ),
        Err(e) => tracing::warn!(error = %e, "TLS leaf renewal task did not complete"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_cert::{generate_ca, issue_leaf, ParsedCa};
    use time::Duration as TimeDuration;

    /// Write a freshly generated CA + leaf (issued `at`) into `paths` so a test can exercise the
    /// loader and the renewal pass. Returns the issue instant so a test can advance the clock past
    /// the leaf's renewal window.
    fn provision_at(paths: &TlsPaths, at: OffsetDateTime) {
        std::fs::create_dir_all(&paths.root).unwrap();
        let ca = generate_ca("test-host", at).unwrap();
        std::fs::write(paths.ca_cert(), &ca.cert_pem).unwrap();
        std::fs::write(paths.ca_key(), &ca.key_pem).unwrap();
        let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
        let leaf = issue_leaf(&parsed, at).unwrap();
        std::fs::write(paths.leaf_cert(), &leaf.cert_pem).unwrap();
        std::fs::write(paths.leaf_key(), &leaf.key_pem).unwrap();
    }

    /// Write a freshly generated CA + leaf into `paths`, issued now.
    fn provision(paths: &TlsPaths) {
        provision_at(paths, OffsetDateTime::now_utc());
    }

    #[test]
    fn load_is_none_when_no_leaf_present() {
        // Fail-soft: an unprovisioned machine (no installer run yet) yields no HTTPS material,
        // so the caller falls back to plaintext instead of failing to start. Uses the inner
        // leaf-loader so the assertion is about leaf ABSENCE, not the owner gate.
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        assert!(load_leaf_material(paths).is_none());
    }

    #[test]
    fn load_is_some_when_leaf_present() {
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        provision(&paths);
        // The inner loader skips the owner gate (a tempdir is user-owned), exercising the leaf
        // parse + resolver-reload path directly.
        let material = load_leaf_material(paths).expect("a provisioned leaf loads");
        // Building the config proves the leaf key parsed as a usable ECDSA signing key, and the
        // resolver re-reads the just-written pair without error (the rotation hot-reload path).
        material
            .resolver
            .reload()
            .expect("reload the just-written leaf pair");
    }

    /// #661: even with a fully provisioned CA + leaf, `load_https_material` must REFUSE when the TLS
    /// root is not privileged-owned — a tempdir is owned by the (non-root/non-SYSTEM) test user, so
    /// the owner gate fails closed to plaintext and `ca.key` is never read on the rotation path.
    #[test]
    fn load_refuses_when_the_tls_root_is_not_privileged_owned() {
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        provision(&paths);
        assert!(
            load_https_material(paths).is_none(),
            "a user-writable TLS root must refuse to load the CA/leaf (#661)"
        );
    }

    /// #660: the renewal ticker's period is the daily interval and its missed-tick policy is `Delay`
    /// (not the default `Burst`), so a host sleep/suspend across several intervals coalesces into ONE
    /// catch-up pass instead of firing a redundant burst of identical passes.
    #[tokio::test(start_paused = true)]
    async fn renewal_ticker_uses_delay_missed_tick_behavior() {
        let mut ticker = new_renewal_ticker();
        assert_eq!(ticker.period(), RENEWAL_INTERVAL);

        // Consume the immediate startup tick, then stall far past several intervals.
        ticker.tick().await;
        tokio::time::advance(RENEWAL_INTERVAL * 3).await;

        // Count how many ticks are ready WITHOUT advancing the clock further. `Delay` coalesces the
        // whole missed backlog into a single catch-up tick; `Burst` would hand back one per missed
        // interval (3 here). A tiny timeout returns `Err` once no tick is immediately ready.
        let mut immediate = 0;
        while tokio::time::timeout(Duration::from_millis(1), ticker.tick())
            .await
            .is_ok()
        {
            immediate += 1;
            assert!(immediate <= 3, "Delay must not burst-fire the missed ticks");
        }
        assert_eq!(
            immediate, 1,
            "Delay coalesces the missed ticks into exactly one catch-up pass"
        );
    }

    /// #659: a rotation pass over a FRESH leaf renews nothing — the leaf is nowhere near its 30-day
    /// window — and leaves the on-disk leaf byte-identical.
    #[tokio::test]
    async fn rotation_pass_leaves_a_fresh_leaf_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        let now = OffsetDateTime::now_utc();
        provision_at(&paths, now);
        let before = std::fs::read(paths.leaf_cert()).unwrap();

        let (_config, resolver) =
            dig_cert::load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();
        let manager = Arc::new(RenewalManager::new(paths.clone(), resolver));
        run_rotation_pass(manager, now).await;

        assert_eq!(
            before,
            std::fs::read(paths.leaf_cert()).unwrap(),
            "a fresh leaf must not be re-issued"
        );
    }

    /// #659: a rotation pass run when the leaf is inside its 30-day renewal window RE-ISSUES the leaf
    /// on disk (the rotation ACTION) and the resolver hot-reloads the new pair. Drives the manager
    /// with a clock 61 days after issue — past the 60-day (90d − 30d) renewal threshold.
    #[tokio::test]
    async fn rotation_pass_reissues_a_leaf_inside_its_renewal_window() {
        let dir = tempfile::tempdir().unwrap();
        let paths = TlsPaths::under(dir.path());
        let issued = OffsetDateTime::now_utc();
        provision_at(&paths, issued);
        let before = std::fs::read(paths.leaf_cert()).unwrap();

        let (_config, resolver) =
            dig_cert::load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();
        let manager = Arc::new(RenewalManager::new(paths.clone(), resolver));
        // 61 days later the 90-day leaf is within its 30-day-remaining renewal window.
        run_rotation_pass(manager, issued + TimeDuration::days(61)).await;

        assert_ne!(
            before,
            std::fs::read(paths.leaf_cert()).unwrap(),
            "a leaf inside its renewal window must be re-issued (the rotation action)"
        );
    }
}
