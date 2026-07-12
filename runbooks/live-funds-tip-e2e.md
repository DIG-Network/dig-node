# Runbook — live-funds `$DIG` tip e2e (§18.12, #428)

The controlled, real-money pass that proves the node's LIVE wallet broadcaster: a `dig-node` with
live broadcast enabled imports the funded test wallet and sends ONE small `$DIG` tip to the DIG
treasury, then confirms it on-chain.

**This moves real mainnet `$DIG`.** It is disabled everywhere by default — it never runs in CI or an
ordinary `cargo test` (it is `#[ignore]`d AND gated on `DIG_LIVE_FUNDS_TEST=1`). Run it only on an
operator machine with network access and the funded test wallet.

## What it does

1. Assembles a served wallet with `enable_live_broadcast = true` — attaches the real
   `ChiaQueryBroadcaster` (`chia_query::push_tx`), `ChiaQueryConfirmer`, `ChiaQueryLineage`, and
   `CoinsetFallback` over one shared `chia_query` client (mainnet).
2. Imports + unlocks the funded test wallet from `DIG_TEST_WALLET_MNEMONIC`.
3. Pins a TINY, single-tip budget: dev tip = **1 base unit (0.001 $DIG)**, creator off, daily cap =
   exactly one tip, zero fee. A bug cannot over-spend beyond one base unit.
4. Triggers ONE `dev_daily_tip()` → the node builds + signs + validates (`dig-clvm`) + broadcasts the
   `$DIG` CAT tip to `digstore_chain::dig::treasury_inner_puzzle_hash()`.
5. Records the `push_tx` txid in the tip ledger (status `Pending`), then polls for on-chain
   confirmation (status flips to `Confirmed`).

## Prerequisites

- A funded test wallet holding a small amount of `$DIG` (≥ 1 base unit) on mainnet, plus enough XCH
  for network fees if you raise `cfg.fee` above zero.
- Network access to Chia peers / `api.coinset.org` (the live client requires ≥ 1 peer at startup).
- The test wallet's 24-word mnemonic, sourced from the git-ignored `/.test-credentials` at the
  superproject root. **NEVER commit, print, or paste it into logs or the shell history.**

## Running it

```sh
# On the operator machine, from the dig-node repo root.
export DIG_LIVE_FUNDS_TEST=1

# Source the mnemonic from /.test-credentials WITHOUT echoing it. Adjust to your credentials format;
# the value must be the 24-word mnemonic. Example (read a KEY=value line without printing it):
export DIG_TEST_WALLET_MNEMONIC="$(grep -m1 '^TEST_WALLET_MNEMONIC=' /path/to/.test-credentials | cut -d= -f2-)"

# Run the single ignored, gated test (real broadcast).
cargo test -p dig-node-service --test live_funds_tip_e2e -- --ignored --nocapture

# Clean up the shell so the secret does not linger.
unset DIG_TEST_WALLET_MNEMONIC
```

Expected output (abridged):

```
live e2e: funded test wallet unlocked at xch1...
live e2e: dev_daily_tip outcome = Tipped { txid: "…", dig_amount: 1, recipient_ph: "ec7c3047…" }
live e2e: broadcast txid = …, status = Pending
live e2e: CONFIRMED on-chain — txid …
test live_funds_dev_tip_broadcasts_and_confirms ... ok
```

Record the txid in the #428 issue comment as the live-broadcast proof.

## Idempotency + re-runs

- The dev tip is once-per-UTC-day. A second run the SAME day cleanly SKIPS (`already-tipped-today`)
  because the persisted ledger reservation blocks it — this is the money-safe idempotency, not a bug.
  To re-run the same day, use a fresh config dir (the test already uses a unique temp dir per run).
- A broadcast that is accepted but not confirmed within 5 minutes leaves the ledger entry `Pending`
  with its txid — the money may have moved. Verify the txid on-chain (e.g. a mainnet explorer /
  `chia_query` coin lookup) before re-running; do NOT assume it failed.

## Safety checklist (verify before running)

- [ ] `DIG_LIVE_FUNDS_TEST=1` is set ONLY for this run (unset it afterward).
- [ ] `DIG_TEST_WALLET_MNEMONIC` is exported without echoing; never committed.
- [ ] The test wallet is the funded TEST wallet (small balance), not a production key.
- [ ] The tip amount + daily cap are the tiny defaults (1 base unit) — do not raise them.
