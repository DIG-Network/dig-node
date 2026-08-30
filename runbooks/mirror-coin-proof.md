# Mirror-coin lifecycle — the step-8 real-machine proof (dig-node#377)

The acceptance bar for <https://github.com/DIG-Network/dig-node/issues/377> is not a green suite. It
is a person funding the node's operating wallet, serving a `.dig`, watching the mirror coin appear at
the epoch's required amount, deleting the `.dig`, and watching the collateral come back.

This runbook is the procedure for that, and — more importantly — the procedure for **disbelieving**
it. Every check below is stated so it can be answered from the coin's own on-chain evidence. A
verifier that only asks the node is not a verifier: the node is the thing under test.

Contract: `SPEC.md` §25. Spend construction is `dig-mirror-coin` 0.7; amounts are
`dig-mirror-collateral` 0.3.

---

## 0. State of the world, measured 2026-08-30

| fact | value | how it was established |
|---|---|---|
| operator wallet address | `xch1323jt04aqgt0fflzve6wygthx9aquhrqe58j8ucg4ttsn44mg62qwyrxn0` | derived from the on-disk `DIGOP1` seed via `OperatorWallet::open` |
| operator puzzle hash | `8aa325bebd0216f4a7e26674e22177317a0e5c60cd0f23f308aad709d6bb4694` | same |
| XCH balance | **0** — and **zero coin records ever**, spent or unspent | coinset.org `get_coin_records_by_puzzle_hash`, `include_spent_coins: true` |
| $DIG balance | **0** — zero hinted records ever | coinset.org `get_coin_records_by_hint` |
| `(store, root)` pairs served | **3** (across 5 hosted stores; 2 hold no capsule) | `dign stores --json` |
| current epoch | **104**, `2026-08-25T00:00Z` → `2026-09-01T00:00Z` | `MIRROR_EPOCH_GENESIS_UNIX_MS` + 7-day window |
| can `main` create a coin today | **no** — no production caller exists | see §1 |

**The wallet has never held anything.** It is not "empty because it was spent"; nothing has ever
arrived at it. Funding it is a prerequisite for step 8 and is the user's decision.

### Why the node's own balance read cannot establish that

`dign wallet balance <addr> --asset dig --json` answers `0` — but it answers it with
`"synced": false`, `"source": "fallback"`, `"peak_height": null`. That is a reassuring zero, not a
measurement: the same output appears for a funded wallet the node has not caught up to. At the time
of measurement the node's replica was at **9,211,798** while its own Chia peers reported
**9,220,177** — about **8,380 blocks**, roughly two days behind.

So the zero above is the *independent* one, and it carries a control: the same coinset.org query
shape run against the DIG treasury hash returns **357** records. A query returning zero on both the
subject and a known-active control would have measured nothing at all.

**This is the first check to repeat before step 8**, because a node two days behind chain cannot
observe its own create confirm.

---

## 1. Nothing on `main` can create a coin today

At `fba53ec`, the mirror module is reachable only from tests:

* `MirrorSigner`, `build_create`, `build_reclaim` — referenced solely by
  `crates/dig-node-service/tests/mirror_fee_ceiling.rs`.
* `dig_mirror_coin::list` — **zero occurrences** in the repo.
* `crates/dig-node-service/src/lib.rs:80` declares `pub mod mirror;` and no other module uses it.

So the merged half decides and signs; nothing observes, schedules, spends, or broadcasts. The
shortest path from here to a coin on chain is the pass runner in
<https://github.com/DIG-Network/dig-node/issues/412> (PR#414). Until it lands, steps 4-7 below cannot
be executed at all — but steps 0 and 2 can, and should, be run first, because they are what turns a
failed proof into a diagnosed one.

---

## 2. Funding — what to send, before anything else

Per pair, per epoch, the posted collateral is
`apply_safety_margin(required_per_store, margin_bp)` (SPEC §25.3).

* `margin_bp` defaults to **100** (`SAFETY_MARGIN_BP_DEFAULT`) — that is **+1%**, and
  `apply_safety_margin` **rounds up**.
* At the genesis schedule figure of `required_per_store = 1000` base units (1.000 $DIG), the amount
  actually posted is therefore **1010 base units = 1.010 $DIG per pair**, not 1.000.

> **A verifier that asserts 1000 will fail a correct create.** Read the epoch's
> `required_per_store_dig_base_units` from the census rather than assuming 1000 — the schedule rises
> toward 5.000 as the handicap decays, and the figure above is the genesis end of it.

For the 3 pairs currently served:

| | base units | $DIG |
|---|---|---|
| one epoch's posting (3 pairs x 1010) | 3,030 | **3.030** |
| rollover peak — the epoch being reclaimed is still locked while the next is posted | 6,060 | **6.060** |

Fund for the **peak**, not the posting. Collateral is reclaimed rather than spent, so the steady
state is roughly one epoch's lock; the peak is two, and it is the term nobody budgets for
(`collateral.rs::buffer_advice`).

**XCH.** The shipped default fee is **0**, and `dig_mirror_coin::reclaim` explicitly supports a
zero-fee reclaim, so XCH is not strictly required. Send a small amount anyway (**~0.01 XCH**): a
zero-fee spend has no mempool priority, and a wallet at zero XCH that later needs a fee is the legacy
bug where a node could be unable to advertise *and* unable to recover what it had already locked
(#377, bug 6). The per-spend ceiling is `MIRROR_SPEND_FEE_CEILING_MOJOS` = 1,000,000,000 = 0.001 XCH.

**$DIG cannot be substituted.** It is a CAT (asset id
`a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81`); sending XCH does not produce it.

Confirm arrival independently — not from `dign wallet balance`, which is subject to the staleness
above — by asking coinset.org for the coin records hinted to the operator puzzle hash
(`get_coin_records_by_hint`, hint `0x8aa325be…4694`, `include_spent_coins: false`).

---

## 3. Baseline, before serving anything

Record, so the create is a *change* rather than an observation:

* `dign stores --json` — the `(store, root)` pairs, and their count
* `dign wallet sync-status --json` — `peak_height` vs `chia_peer_peak_height`, which must be close
* `dign spends --json` — the audit ledger, BEFORE

Capture the full set of mirror coins already at the mirror puzzle hash (§5 explains why this
baseline is load-bearing).

---

## 4. Create — serve a `.dig` and watch the coin appear

1. Ensure collateralisation is ON (`collateral.json`, defaults on).
2. Bring a `.dig` into the cache with **`Held`** provenance and let it verify. `Relayed` capsules
   are served but never advertised (SPEC §25.1), so a `Relayed` capsule producing no coin is
   **correct behaviour**, not a failure — check provenance before diagnosing a missing coin.
3. Wait for the reconcile pass (#412's cadence).
4. `dign spends --json` should gain exactly **one** entry per created coin, with
   `kind: "mirror-coin"`, `authority: { principal: "node", grant: "mirror-collateral" }`,
   `asset: "dig"`, the amount in DIG base units, the fee in XCH mojos, and the `store_id`.

---

## 5. Verifying the create from the coin's own evidence

**The trap this section exists for:** `mirror_coin_puzzle_hash()` is *the same value for every owner
and every coin in the network*. The collateral puzzle takes its authority from the coin's parent, not
from a curried key, so ownership lives in the lineage proof. A scan of that puzzle hash finds
**everyone's** collateral. "A coin appeared at the mirror puzzle hash" is therefore evidence of
almost nothing — it is satisfied by a stranger's coin created in the same window.

Six checks. Each rules out a different way a coin could look right and be wrong.

| # | check | what it rules out |
|---|---|---|
| 1 | The coin sits at `dig_mirror_coin::mirror_coin_puzzle_hash()` | a coin at an unrelated address |
| 2 | Fetch its **creating spend** (the parent's spend) and run `MirrorCoin::from_creating_spend(spend, coin_id)` → `Ok(Some(_))` | a coin whose properties were asserted rather than executed — this derives the asset id, amount and owner by running the parent's puzzle |
| 3 | `coin.owner_puzzle_hash() == 8aa325be…4694` | **somebody else's coin.** This is the check the puzzle hash cannot make, and the one most likely to be skipped |
| 4 | `coin.advertises(store_launcher_id, root_hash, &BigInt::from(104))` → `true` | a coin for a different store, a different root, or a **previous epoch**; and a coin that declares one tuple while being indexed under another (it checks both the declared tuple and the hint) |
| 5 | `coin.collateral()` equals `apply_safety_margin(required_per_store, margin_bp)` for epoch 104 | the right coin at the wrong amount |
| 6 | The coin id is **absent from the §3 baseline** and its creating spend is at a height **after** funding | a pre-existing coin, or one that merely appeared during the window |

Checks 3 and 4 are the load-bearing pair, and neither substitutes for the other: check 4 without
check 3 accepts a coin bonding this store on somebody else's behalf, and check 3 without check 4
accepts this wallet's coin for a *different* root or a *stale epoch*.

The asset id is re-derived by check 2 rather than read from a memo. A memo is chosen by whoever spent
the parent; the executed conditions are not.

**Note the sibling-coin filter is necessary, not sufficient.** `from_creating_spend` returns
`Ok(None)` for a collateral coin carrying no advertised URLs, which keeps honest neighbours out of
the result. Memo shape is attacker-chosen, so it filters neighbours rather than defeating an
adversary — do not treat "it parsed as a mirror coin" as an authentication step. Check 3 is the
authentication step.

---

## 6. Reclaim — two ways to trigger it, and one is free

**By deleting the `.dig`** (the `NoLongerHeld` path): delete or unpin the capsule, wait for the next
pass. This is the path #377's acceptance names.

**By epoch rollover** (the `EpochEnded` path): epoch 104 ends at **`2026-09-01T00:00Z`**. If a coin
exists before then, the rollover reclaim can be watched without deleting anything — the pass creates
epoch 105's coins and reclaims epoch 104's on the same pass. This leg is otherwise expensive to
observe, since it needs a week of waiting.

Reclaims run **regardless of the collateral switch** and are never gated on funds or on a known
requirement — a reclaim's amount is read from the coin being reclaimed, so recovering money never
waits on a census (SPEC §25.3, §25.7).

### Verifying the reclaim returned the FULL locked amount

1. The mirror coin is **spent** — its coin record shows `spent: true` at a known height.
2. Its spend created a coin **at the operator's own puzzle hash** `8aa325be…4694`.
3. That created coin is **$DIG**, asset id re-derived from the spend, not assumed.
4. Its amount equals the reclaimed coin's `collateral()` **exactly** — not the current epoch's
   requirement. A coin locked under a previous epoch's amount returns *that* amount. Comparing
   against today's requirement will read a correct reclaim as wrong the moment the schedule moves.
5. The wallet's $DIG total returns to its pre-create value, read independently as in §2.

> A reclaim that returns *less* than was locked is the failure this whole section is for. The crate
> recreates the full amount at the owner's puzzle hash and there is no supply-reducing path, so a
> shortfall means the reclaim did not happen the way it appears to have.

---

## 7. Telling a real proof from a plausible-looking one

The five ways this proof can go green while proving nothing:

1. **The node's word.** `dign` reads the node's replica, which was two days stale when measured. Every
   amount and every confirmation is corroborated against coinset.org or another independent source.
2. **A stranger's coin.** Everyone's collateral is at one puzzle hash. Without check 3, an unrelated
   coin created in the same window passes every other check.
3. **A previous epoch's coin.** `advertises` takes the epoch explicitly for this reason. Assert epoch
   **104**, and after `2026-09-01T00:00Z`, **105**.
4. **A confirmation on the wrong coin.** The legacy waited for the *funding* coin to be spent, which
   a competing spend satisfies identically, and so never confirmed the mirror coin existed (#377, bug
   5). Confirm by observing the **created** coin (SPEC §23.2).
5. **A zero that means "not synced".** The reassuring zero in §0. Any zero in this procedure is
   accompanied by a control that returns non-zero, or it is not a reading.

---

## 8. What is still needed before this can be run

| need | owner | state |
|---|---|---|
| the reconcile pass — observe disk + chain, schedule, spend, broadcast, record | #412 / PR#414 | in flight; **blocks steps 4-7 entirely** |
| the per-store state surface (`bonded`/`unfunded`/`deferred`/`withheld`) | #377 step 6 | pending; without it, "out of funds" and "withheld on purpose" cannot be told apart from the CLI |
| a way to learn the operator address from a shipped surface | **unfiled** | no `dign` verb prints it; the address above was derived by opening the seed with a scratch example. **A user cannot fund a wallet whose address the product will not tell them** |
| operator wallet funded (at least 6.060 $DIG for 3 pairs, plus ~0.01 XCH) | user | **not funded; never funded** |
| node caught up to chain | node | ~8,380 blocks behind at measurement |
