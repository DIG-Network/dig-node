//! LIVE-FUNDS end-to-end test (§18.12, #428) — REAL mainnet `$DIG` broadcast.
//!
//! This is the ONLY test that can move real money, and it is **SKIPPED by default**. It runs a
//! `dig-node` wallet with live broadcast ENABLED, imports the FUNDED TEST wallet, and triggers ONE
//! small `$DIG` dev tip to the DIG treasury puzzle hash
//! (`digstore_chain::dig::treasury_inner_puzzle_hash()`), asserting a real `push_tx` + on-chain
//! confirmation.
//!
//! ## Money-safety (HARD)
//! - **CI never reaches this path.** The test early-returns (a logged skip) UNLESS `DIG_LIVE_FUNDS_TEST=1`.
//! - **The mnemonic is NEVER inlined or logged.** It is read from `DIG_TEST_WALLET_MNEMONIC`, which the
//!   operator exports from `/.test-credentials` (git-ignored) per `runbooks/live-funds-tip-e2e.md`.
//! - **Capped + tiny.** The tip amount is pinned to `TIP_BASE_UNITS` (default 1 base unit = 0.001 $DIG)
//!   and the daily cap to exactly one such tip, so a bug can never over-spend.
//! - **Idempotent.** The dev tip is once-per-UTC-day; a re-run the same day cleanly skips.
//!
//! ## Running it
//! See `runbooks/live-funds-tip-e2e.md`. In short (operator machine, funded wallet, network):
//! ```sh
//! export DIG_LIVE_FUNDS_TEST=1
//! export DIG_TEST_WALLET_MNEMONIC="$(...)"   # sourced from /.test-credentials, never committed
//! cargo test -p dig-node-service --test live_funds_tip_e2e -- --nocapture --ignored
//! ```

use std::time::Duration;

use dig_wallet::sage::service::{WalletService, WalletServiceConfig};
use dig_wallet::sage::tipping::TipStatus;

/// The tip amount for the live pass: 1 base unit = 0.001 $DIG (`DIG_DECIMALS = 3`). Tiny + capped.
const TIP_BASE_UNITS: u64 = 1;

/// A unique temp config dir for the e2e wallet (isolated from any real node state).
fn scratch_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dig-node-live-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// End-to-end: a real mainnet `$DIG` dev tip that broadcasts + confirms. Gated + `#[ignore]` so it
/// never runs in CI or an ordinary `cargo test`; the operator opts in per the runbook.
#[tokio::test]
#[ignore = "moves real mainnet $DIG — run only with DIG_LIVE_FUNDS_TEST=1 + the funded test wallet (see runbooks/live-funds-tip-e2e.md)"]
async fn live_funds_dev_tip_broadcasts_and_confirms() {
    // ── Gate 1: the explicit opt-in env. Without it, this is a no-op skip (belt-and-suspenders
    // beside `#[ignore]`, so even a `--ignored` sweep on a normal machine can't spend). ──
    if std::env::var("DIG_LIVE_FUNDS_TEST").as_deref() != Ok("1") {
        eprintln!(
            "SKIP live_funds_dev_tip_broadcasts_and_confirms: set DIG_LIVE_FUNDS_TEST=1 (and \
             DIG_TEST_WALLET_MNEMONIC) to run the real-money pass — see runbooks/live-funds-tip-e2e.md"
        );
        return;
    }

    // ── Gate 2: the funded test wallet mnemonic, by env (exported from /.test-credentials — NEVER
    // inlined or logged). Absent-while-gated is a hard, explicit failure. ──
    let mnemonic = std::env::var("DIG_TEST_WALLET_MNEMONIC").expect(
        "DIG_LIVE_FUNDS_TEST=1 requires DIG_TEST_WALLET_MNEMONIC (export it from /.test-credentials; \
         never commit or print it)",
    );
    let password = "live-funds-e2e-password";

    // ── Assemble a LIVE wallet (real chia_query broadcaster + confirmer + lineage + fallback). ──
    let dir = scratch_dir();
    let svc = WalletService::build_with(
        &dir,
        WalletServiceConfig {
            enable_live_broadcast: true,
        },
    )
    .await;

    // Import + unlock the funded test wallet (persist_and_unlock loads the signer). NEVER logs the
    // mnemonic.
    let custody = svc
        .backend
        .custody()
        .expect("live wallet must carry node custody");
    let address = custody
        .import(&mnemonic, password)
        .expect("import + unlock the funded test wallet");
    eprintln!("live e2e: funded test wallet unlocked at {address}");

    // Pin a TINY, single-tip budget: dev tip = TIP_BASE_UNITS, creator off, daily cap = one tip,
    // zero fee. A bug cannot over-spend beyond one base unit.
    let engine = svc
        .backend
        .tipping()
        .expect("live wallet serves the tipping subsystem")
        .clone();
    let mut cfg = engine.get_config().await;
    cfg.creator.enabled = false;
    cfg.dev.enabled = true;
    cfg.dev.dig_amount = TIP_BASE_UNITS;
    cfg.daily_total_cap = TIP_BASE_UNITS;
    cfg.fee = 0;
    engine.set_config(cfg).await.expect("set tiny tip budget");

    // ── Trigger the ONE real dev tip (pays the DIG treasury). Money moves here. ──
    let outcome = engine
        .dev_daily_tip()
        .await
        .expect("dev tip must not error");
    eprintln!("live e2e: dev_daily_tip outcome = {outcome:?}");

    // The ledger must record exactly one entry with a real broadcast txid.
    let ledger = engine.get_ledger(None).await;
    assert_eq!(ledger.len(), 1, "exactly one tip was attempted");
    let entry = &ledger[0];
    let txid = entry
        .txid
        .clone()
        .expect("a broadcast tip records its push_tx txid");
    assert_eq!(entry.dig_amount, TIP_BASE_UNITS, "the capped tiny amount");
    eprintln!(
        "live e2e: broadcast txid = {txid}, status = {:?}",
        entry.status
    );

    // Poll the ledger for on-chain confirmation (the confirmer flips Pending → Confirmed as the
    // block lands). Allow generous mainnet block time.
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        let entry = engine
            .get_ledger(None)
            .await
            .into_iter()
            .find(|e| e.txid.as_deref() == Some(txid.as_str()));
        match entry.map(|e| e.status) {
            Some(TipStatus::Confirmed) => {
                eprintln!("live e2e: CONFIRMED on-chain — txid {txid}");
                break;
            }
            Some(TipStatus::Failed) => panic!("the tip broadcast was recorded Failed (ambiguous)"),
            _ if std::time::Instant::now() >= deadline => panic!(
                "tip {txid} was broadcast but not confirmed within the window; verify on-chain \
                 manually (money may have moved)"
            ),
            _ => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
