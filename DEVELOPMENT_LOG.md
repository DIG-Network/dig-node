# Development Log — dig-node

High-signal realizations from debugging/development: non-obvious cross-system couplings,
sharp edges, and gotchas. Concise durable facts with context — NOT a change diary. See
`CLAUDE.md` §4.5 for the maintenance contract (a curator periodically re-verifies + prunes).

## The mirror lifecycle observes correctly on a real machine, and `entries: []` there is a truth (#433)

Measured 2026-08-31 on Windows 11 against a `dign` built from `9eb8fbd` (0.179.0), run with
`RUST_LOG=mirror=debug`. The whole step-7 lifecycle is exercised at bring-up and answers:

```
$ dign mirror bond-states --json
{"ok":true,...,"state":"known","entries":[],"complete":true,"cursor":null,
 "locked_dig_base_units":0,"epoch":104}

INFO  mirror: the mirror lifecycle is live: this node may create and reclaim collateral
DEBUG mirror: mirror pass complete epoch=104 bonds=0 locked_dig_base_units=0 reclaimed=0 created=0
```

Three durable facts, each of which has already cost a wrong conclusion once:

- **A `chain_unreadable` reading is only evidence about the binary that produced it.** #433 was
  filed from installed `dign 0.172.0` = `6e8bfa7`, and step 7 (`5df3e34`) is not an ancestor of it.
  That binary carried the stub, which answers `unknown { chain_unreadable }` by construction and
  runs no pass at all. Before treating a mirror reading as a symptom, check
  `git merge-base --is-ancestor <fix> $(git rev-list -n1 <version>)`.

- **`entries: []` and a fabricated zero look identical on the wire, and are told apart by `state`.**
  `state: "known"` with `complete: true` and a named epoch is a published observation from a pass
  that genuinely read the chain — here, truthfully, that this node has never created a mirror coin.
  The `Err` arms in `spawn_mirror_passes` deliberately do NOT publish, precisely so an empty page
  can never mean "the read failed". Resolving a mirror `unknown` by returning an empty page would
  destroy that distinction; it is a claim about money.

- **`chain_unreadable` is the catch-all for five structurally different states**, only one of which
  is a chain read failing: `enable_chain_sync == false` (no task is ever spawned), no operator
  wallet (the task `return`s *permanently*), no epoch in force, `chain_source()` `Err`, and
  `pass.run()` `Err`. The first two are terminal, not transient, so a node in either answers
  `chain_unreadable` forever while its chain reads work perfectly — which sends an operator to
  inspect peers that are fine. None was in force in this reading. Naming them needs a wider
  `MirrorBondStatesUnknownReason`, which lives in `dig-node-control-interface` and is therefore a
  release-first change rather than a dig-node edit.

**What a mirror CREATE still needs, measured the same session.** Two independent blockers, so the
#412 step-8 create/reclaim proof is not reachable by configuration alone: this node caches zero
capsules (`observe_disk` reads `cache_list_cached`, and both pinned stores hold `capsule_count: 0`),
so there is no `(store, root)` to bond; and it has no publishable advertise URL (#426), so `create`
refuses by name ahead of any chain read. The advertise slot is not a formality to fill in — its
value is written to chain as a claim about where this node can be fetched, so an invented URL is a
permanent false advertisement on a money artifact.

## Two workflows assemble one release, so whichever finishes first used to publish it half-built (#335)

A stable `vX.Y.Z` release of dig-node is built by **two** workflows that neither know about nor wait
for each other: `release.yml` attaches the ten raw binaries (`dig-node-*`, `dign-*`) and
`package.yml` attaches the four native install packages (`.deb`/`.pkg`/`.msi`). Both used
`softprops/action-gh-release`, **whose `make_latest` defaults to true**, so *attaching assets* was
also *promoting the release* — and the promotion was won by whichever job finished first.

On v0.145.0 that was `package.yml`, at `01:47:49Z`. The binaries landed at `01:52:52Z`. For those
five minutes `releases/latest` was a release carrying four packages and no binaries at all, and
dig-installer resolves both the `dig-node` and `dign` stems through `releases/latest`
(`dig-installer/src/release.rs:187`), so **every fresh install 404'd** — with no red anywhere,
because both workflows genuinely succeeded at the job each was given.

Two durable lessons:

- **`releases/latest` is a user-facing pointer, not a bookkeeping detail.** The instant it moves,
  users are served that release. It must be moved by ONE step that runs last and knows the whole
  asset set — never as a side effect of an upload. `make_latest: false` on both publishers plus a
  `promote` job gated on the asset guard is the shape.
- **A guard is only as wide as the consumer list it was written against.** The asset guard existed
  and reported success on this release, because it had been written for dig-updater's feedsign and
  knew only the four package names. dig-installer was a second consumer nobody had told it about.
  When a check enumerates what a release must carry, enumerate *per consumer*, and make the guard
  falsifiable — the self-test in `verify-release-assets.yml` fails the build if the guard ever again
  passes an asset list carrying only the packages.

Corollary for diagnosis: a release asset set is a **race**, so measuring it once during a release
run tells you the state at that instant and nothing about the outcome. Read the assets'
`created_at` against the release's `published_at` before concluding assets were never attached.

## `initial_sync_complete` can NEVER latch on a default install — so it cannot mean "synced" (dig_ecosystem#2609)

`sync_state.initial_sync_complete` is written by exactly one statement, `WalletDb::complete_catch_up`,
whose only caller is `sync::initial_sync`. `Supervisor::run` skips that call entirely when the
puzzle-hash set is empty. A node with no wallet enrolled therefore holds the flag at `false`
**permanently** — not transiently — while `run_update_loop`'s `NewPeakWallet` arm keeps advancing
`sync_state.peak_height` with the chain for an authoritative peer.

The trap: the flag reads like "is this replica caught up", so a derived status naturally spells
`false` as *"still catching up"*. On the commonest install in existence that sentence is false — the
replica is AT the tip. It cost a user-visible defect: dig-app withheld the balance for ever behind
"your node is still catching up with the blockchain", on a node whose peak was advancing the whole
time. **Read the flag as "a catch-up has completed", never as "the replica is current"; they differ
precisely when there is nothing to catch up on.**

Do not fix that by latching the flag over an empty set. `sage::routing::route` treats
`initial_sync_complete` as permission to serve wallet-scoped reads from the local DB, so latching it
over an un-queried replica makes a funded wallet read as empty — which is why `initial_sync` refuses
the empty set at the floor in the first place. The honest fix is a separate state
(`SyncPhase::NoWalletEnrolled`).

**The sharp edge when deriving that state:** "the session subscribed nothing" is NOT the same fact as
"custody holds nothing". `Supervisor::run` FORCES the subscription set empty for an uncorroborated
peer, so an empty set also describes a refused writer whose replica is deliberately not being written
and IS falling behind. Keying a benign state on the empty set alone reports a stalled replica as
healthy. The gate needs the trust fact too — and a measured-vs-unmeasured distinction
(`Option<u32>`, not `u32`), because corroboration dials four peers before the set is decided and a
`0` default would announce "nothing to watch" during every connect.

Observed live, which is how the trust half was caught: a fresh node reported
`{"phase":"syncing","peak_height":null,"chia_peer_count":1,"watched_addresses":0}` — empty set,
still syncing, correctly — and only settled once its peer was authoritative.

## Arrival detection: a height watermark alone silently eats the coins it is meant to gate (#2548)

Announcing "you were paid" needs a line between the address history a catch-up replays and money that
is genuinely new. The obvious line is a persisted height watermark — record coins above it, advance it
to the peak each pass — and it is wrong in a way that shows up only as SILENCE, never as a wrong claim,
which is why it survives review.

Two coins fall through it, and both are ordinary:

* **A coin sighted in the mempool and confirmed at the height the pass is advancing to.** It is
  unconfirmed when examined, so it is not recorded; the watermark then moves to that same height, and on
  the next pass the coin reads as backfill. `<=` versus `<` does not fix it — the coin WAS examined, and
  legitimately not judged.
* **A CAT whose asset id has not been attributed yet.** `asset_id` is filled in by a LATER parent-spend
  uncurry pass, so at examination time the coin cannot be named. Announcing it as XCH is a wrong claim
  about which money arrived; skipping it means the watermark passes it and it is never announced at all.

The fix is that "examined" and "settled" are different states: a coin the recorder saw and deliberately
did not judge is HELD, and a held coin is EXEMPT from the height window until it settles. Both defects
were caught only by the POSITIVE CONTROL half of the trap tests — the negative assertions ("no arrival
was recorded") passed happily against a recorder that had lost the money. A negative assertion about a
notification is satisfied by any amount of silence, so each one needs a paired coin that differs in
exactly the tested dimension and IS recorded.

Two structural facts about this wallet bound what such a feature can honestly claim:

* **The direct-peer sync path cannot see CAT coins at all.** `apply_coin_states` drops every coin whose
  puzzle hash is outside the subscribed set, and that set is the wallet's bare p2 hashes, while a CAT
  lives at `CatArgs::curry_tree_hash(asset_id, p2)`. CAT coins reach the replica only through
  `refresh_tracked_coins`' hinted coinset read, which is not a background loop — so a CAT arrival is
  detectable only on the oracle tier today. The useful converse: a coin AT a watched p2 hash is a
  standard-transaction coin by construction, so naming it XCH is a fact rather than a guess.
* **There is no record of the wallet's own outbound spends.** `get_pending_transactions` returns an
  empty list by construction and history is derived after the fact by grouping coins on height, so the
  ONLY discriminator between an incoming payment and the user's own change is whether the new coin's
  `parent_coin_info` names a coin the wallet already holds. That test is sound in the direction that
  matters, but only if it runs AFTER the batch commits: a parent and its change coin arrive in the same
  `coin_state_update` frame in whatever order the peer chose, so answering it inside the write races the
  batch and reports the user's own change as a receipt.

## A dependency gate keyed to "the crates.io tip" is unsatisfiable, not strict (#178)

The first draft of `scripts/check-dig-constants-current.sh` refused a stable tag unless
`dig-constants` was SINGLE and equal to the published tip. It was fully tested and provably fired —
and it could never have passed. Both halves are unreachable for structural reasons worth
remembering, because they generalize to any "must be current" dependency gate:

**"Current" is unreachable across a transitive-dependency line jump.** `dig-constants` 0.10.0 moved
to `chia-protocol` 0.36.1 / `chia-wallet-sdk` 0.34 while this repo builds on 0.26 / 0.30, including
the `chia-protocol` fork `dig-gossip` vendors through `[patch.crates-io]`. Adopting 0.10 links a
SECOND `chia_protocol` and produces 11 errors shaped `expected BytesImpl<32>, found
chia_protocol::bytes::BytesImpl<32>` — the tell that two copies of one type are in the graph, not
that a signature changed. This recurs on every chia-line jump, for every consumer, forever.

**"Single" is not fixable by the consumer.** The copies are pinned by PUBLISHED metadata: `dig-gossip`
`>=0.2,<0.5`, `dig-nat` 0.18.0, `digstore-chain` `^0.5`, `dig-download` 0.17.0. No edit in this repo
collapses them; it takes a cross-repo publish cascade (dig_ecosystem#2072).

The lesson is to gate on the PROPERTY the gate exists to protect, not on a proxy that happens to
imply it. Here the property is "no copy predates the real DIG L2 genesis challenge", so the rule is a
0.4.0 FLOOR — and every release from 0.4.0 up is value-NEUTRAL for this repo, since the full
`DIG_MAINNET` const body is byte-identical across 0.4.0 / 0.5.1 / 0.8.0 / 0.9.0. Tip-equality caught
the placeholder only incidentally, at the price of periodically banning releases.

And a gate that blocks on a condition only ANOTHER repo can fix does not hold a line — it gets
bypassed the first time someone needs a release, which teaches everyone that the gate is noise. That
is why duplication warns (naming the holder of each copy, read out of the same lock) while the floor
blocks.

## A tag push can succeed and create ZERO workflow runs (dig_ecosystem#2290)

`git push origin vX.Y.Z` reporting `* [new tag] v0.99.9 -> v0.99.9` does NOT mean a `push: tags:`
workflow ran. On 2026-08-06 that push landed and GitHub created **no** runs from it — neither
`release.yml` nor `package.yml` — while the `HEAD:main` push one second earlier in the same step
DID create one. So this was not an outage, a disabled workflow, or the documented
`GITHUB_TOKEN`-does-not-retrigger rule (the tag was pushed by `RELEASE_TOKEN`, as the eleven
preceding tags were, and `package.yml` has fired on tags 55 times). Run creation from a push event
is effectively at-most-once, and a release path that assumes otherwise has a silent single point
of failure. **Never treat a successful tag push as proof the release fired — confirm the run
exists, and dispatch against the tag ref if it does not** (`ref_type == 'tag'` publish gates are
satisfied by a dispatch selected against a tag, which is what makes the repair equivalent).

Two traps around it. **Reading run history by recency lies:** `package.yml`'s ten most recent runs
were all `event=pull_request`, which reads as "this has never fired on a tag" — filter by
`?event=push` before concluding a trigger is dead. And **a partial manual repair is worse than
none:** dispatching `release.yml` alone produced a `latest` release of bare binaries, and because
dig-updater's feedsign resolves dig-node by native-package file names and fails closed on the
ENTIRE manifest, that froze — then expired — stable auto-update for all five components, dig-app
included. A dig-node release without its `.msi`/`.pkg`/`.deb` is not a partial dig-node release,
it is an ecosystem-wide auto-update outage.
## `read_chunk` is O(global_index) — per-reference lookup is a quadratic CPU-DoS (#2246)

`digstore_core::datasection::read_chunk(pool_body, i)` re-walks the length-prefixed `ChunkPool` from
offset 0 on EVERY call (no offset table). The admit gate's `content_leaves` called it once per
`chunk_index`, so resolving N references over an M-chunk pool was Θ(N·M). The byte cap
(`total_referenced_bytes > MAX_STORE_BYTES`) keys on `ciphertext.len()`, so ZERO-LENGTH chunks add 0 and
never trip it — an attacker sends a pool of M zero-length chunks + one current-gen entry referencing
index `M-1` N times ⇒ ≈Θ(module²) iterations (a ~10 MB module ⇒ ~10^12) with the accumulator stuck at 0,
pinning a core per unauthenticated reshare request. Fix: PRE-INDEX the pool once into per-chunk byte
ranges (O(1) lookup ⇒ recompute is O(pool + refs)) AND cap cumulative references at `MAX_STORE_BYTES / 4`
(defense-in-depth for the zero-length case the byte cap can't see). Lesson: any per-item call into a
scan-from-start reader over attacker-sized input is silently quadratic; index once.

## Admit gate must recompute from CONTENT, not from the attacker's MerkleNodes digests (#2246/#2240)

`ChainAnchoredModuleVerifier` (the capsule-admit gate shared by the reshare-admit pull AND the
`cache.pushCapsule` land via `verify_capsule_integrity`) once only byte-compared the capsule's committed
`CurrentRoot` header against the chain-anchored root. A first fix RECOMPUTED
`MerkleTree::from_leaves(decode_merkle_leaves(MerkleNodes)).root()` — but that was HOLLOW and adversarial
verification refuted it. Rule 4 already forces `committed_root == chain_root` (a public value); a
one-leaf tree's root IS that leaf (`from_leaves` does NOT re-tag leaves — `LEAF_TAG` is applied only in
`build`, and there is no fold for a single leaf); and `decode_merkle_leaves` accepts arbitrary bytes. So
`MerkleNodes = [chain_root]` plus an empty or garbage `ChunkPool` recomputed to the committed root FOR
FREE — admitting, caching, serving, and DHT-announcing a contentless phantom-holder capsule. Trusting
attacker-supplied digests for an admit decision proves nothing.

The gate now recomputes the root from the SERVED CONTENT: for each `KeyTable` (id 8) entry, gather its
chunk ciphertexts from the `ChunkPool` (id 9) via `datasection::read_chunk`, `leaf =
merkle::resource_leaf(serving::concat_output(cts))`, SORT the `(static_key, leaf)` pairs ASCENDING by
`static_key`, then fold `MerkleTree::from_leaves`. The sort is load-bearing: the producer
(`digstore-store` `store.rs`) sorts `resource_leaves.sort_by_key(|r| r.0)` before folding, but KeyTable
storage order is NOT guaranteed sorted, so recomputing in storage order yields the wrong root for ≥2
resources. `MerkleNodes` is retained ONLY as a defense-in-depth cross-check (its leaves must equal the
sorted content leaves, since the served inclusion proofs are generated from it) — never as the trust
anchor. Fail-closed on an absent `KeyTable`/`ChunkPool`, an out-of-range chunk index, an undecodable
section, or a `MerkleNodes`↔content mismatch. A legitimately EMPTY store (no entries) folds to
`from_leaves(vec![]).root() == sha256(&[])` and MUST be admitted, not errored (§5.1). Lesson: an
integrity gate must bind the BYTES it will serve, never a sibling digest field the same attacker chose.

The content recompute is CURRENT-GENERATION-SCOPED (#2246 gen-scoping fix): the embedded `KeyTable` is
MULTI-generation (`digstore-compiler` `key_table.rs` pushes one entry per (generation, resource), each
stamped `entry.generation = gen.root()`), but the committed `CurrentRoot` is folded over the CURRENT
generation ONLY (`pipeline.rs` → `current_generation_leaves(generations.last())`, whose `gen.root()` ==
`CurrentRoot`). Folding EVERY entry over-counts leaves, so ANY store published then updated even once
(≥2 generations — the normal lifecycle) was false-rejected `NotAnchored`, breaking admit/cache/announce.
Fix: fold only entries where `entry.generation.0 == committed_root`. The single-generation fixtures
missed this — a faithful multi-gen fixture is now the regression. Also DoS-bounded (#2246): `chunk_indices`
is attacker-controlled and legitimately permits REPEATED indices (the producer dedups chunks — identical
or shared chunks yield repeated/non-increasing global indices, so repeats can't be banned), so a ~1 MB
module with `chunk_indices=[0;N]` over one large chunk would `concat_output` gigabytes and abort the
allocator. Fix: STREAM each ciphertext into an incremental SHA-256 (`resource_leaf(concat)==sha256(ct0++ct1++…)`
since `resource_leaf` is plain sha256 and `concat_output` is plain concat → O(1) memory) AND cap total
referenced bytes at `MAX_STORE_BYTES` (bounds CPU). Lesson: recompute-from-content must scope to the
producer's committed generation AND bound attacker-controlled index fan-out.

## Local-RPC authz — holder-REVEALING reads gate too, not just mutators (#2108)

Holder-revealing `cache.*` READS must be control-token-gated over the HTTP (loopback) surface, not
just the holder-MUTATING ones (`fetchAndCache`/`pushCapsule`). `cache.listCached` enumerates the
operator's cached-capsule inventory (storeId:rootHash, sizes, LRU order), deanonymizing consumed
content, so a cross-site page POSTing to `dig.local` (DNS-rebinding / local-service attack) could read
it. The gate lives at the transport (`server.rs` `rpc`), not the core dispatch handler. The #2032
WS-parity lesson applies to reads too: verify the second (`/ws`) transport before declaring a method
gated — here `cache.*` is NOT WS-routable because `ws_dispatch`'s fall-through hits `WalletBackend::
dispatch`, whose match has no `cache.*` arm (returns "unknown method"), so the HTTP gate is the only
reachable surface. FFI/in-process callers never reach the HTTP handler and stay open.

## Authority validation is not memory backpressure — bound the reassembly state too (#2149)

`cache.pushCapsule` reassembles chunked capsule uploads in a process-wide `HashMap<(cache_dir,
capsule), PendingPush>`. The §21.6/§21.9 authorized-writer signature and the merkle-integrity check
are only validated on the COMPLETING window (after the whole capsule is buffered) — and, on the peer
surface, only signature *presence* is checked before the first byte is buffered. So with
`DIG_NODE_PUSH_OPEN=true`, any self-signed mTLS peer could open many distinct `(store_id, root)`
partials, never complete them, and pin memory until restart. Authority ≠ backpressure: a gate that
runs after buffering does nothing to bound the buffer.

Durable points:

- **Bound in-flight state on the NON-SPOOFABLE identity, before buffering.** The fix keys a
  per-requestor concurrent-push cap on the same `RequestorId` (verified `peer_id` / loopback operator)
  the #2007/#2189 miss-lookup limiter uses — never on anything in the request body. Pair it with a
  global entry cap (stops identity-cycling), a global pending-BYTES budget (the real memory bound —
  windows accumulate toward `total_length`, so counting entries is not enough), and a lazy TTL reaper
  (an abandoned partial is reclaimed on the next call, no background task).
- **Make the bound one pure, injectable method.** Enforcing every cap in `PendingPushes::admit_window`
  (limits as struct fields, clock passed in) let the tests drive the exact reject paths and the reaper
  on a local instance with an injected `Instant` — no wall-clock sleep, no mutating the shared static
  (which would flake sibling tests running in parallel).
- **A new JSON-RPC code needs a catalogue check, not a "looks free" guess.** The first cut minted
  `PUSH_PENDING_LIMITED = -32015`, but `-32015` was already `METADATA_TOO_LARGE` (dig.getMetadata,
  #2145/#2160) — two conditions colliding on one code silently breaks the deterministic error
  catalogue (§6.2, agents branch on the code). Reassigned to the genuinely free `-32016` in the
  bounded/resource cluster and registered it as a named `ErrorCode` variant so the machine-readable
  catalogue (`meta::error_catalogue`) stays complete. Rule: `git grep` the numeric range across the
  crate AND the docs mirror before assigning a code; the dig-node `-320xx` codes are LOCAL consts (not
  from `dig-rpc-types`), so there is no compiler check for collision — the catalogue is the only guard.

## A service account's home is not a place to keep credentials (#2210)

Every `control.wallet.balance` answered `-32040 WALLET_NO_CHAIN_SOURCE` on an otherwise healthy
node. The chain: `chia-query` resolved its peer TLS certificate under `dirs_home()/.chia`, and
dig-node runs as a Windows service under SYSTEM, whose home is
`C:\Windows\system32\config\systemprofile` and has no `.chia` at all. The certificate was
generated fine and the *write* of it failed (`os error 3`), so `ChiaQuery::new()` failed,
`build_live_wallet()` returned `None` by design, and the wallet fell back to `EmptyFallback`,
whose `is_live() == false` is exactly what the balance read reports as `-32040`.

Three durable points, each of which cost time:

- **Chia peer TLS does not authenticate the client certificate — any well-formed one works.** So a
  certificate on disk was never a credential, only a dependency. Generating one in memory
  (`TlsIdentity::Generated`, chia-query 0.6) removes the filesystem from the path entirely. Two
  earlier remedies — lazy cert loading, a service-appropriate cert directory — were both elaborate
  ways to satisfy a requirement that did not exist.
- **A keyless tier must not sit behind a credentialed one.** The coinset fallback is plain HTTP and
  needs neither cert nor peer, yet the whole client failed to construct before it was reachable.
  chia-query 0.6 makes peers `Optional` whenever the coinset tier is enabled, so an empty peer pool
  degrades to HTTP reads instead of denying the reader the fallback that exists for that case.
- **The bug hid on developer machines because it depended on ambient filesystem state.** An
  interactive user has `~/.chia`; the service account does not. Any test that merely constructed a
  client passed on the machine where the bug was reported. The regression tests therefore assert
  the CONFIGURATION (identity is `Generated`, coinset stays enabled) rather than construction
  success, which makes them independent of whose home directory the suite runs in.

Sharp edge — **a service has no stderr.** The one message explaining the failure was an
`eprintln!`, so it was discarded on every run: 8,000 log lines across three restarts contained
nothing, and the answer sat in that string. Diagnostics in this repo go through `tracing` to the
`dig-logging` sink, never a raw stream. Adopting 0.6 removed the most common reason to reach that
line but not the others (no network, coinset outage), so the log route matters independently.

Sharp edge — **a load-bearing version pin can be held in place by code nothing calls.**
dig-node-core pinned `chia-query = "=0.5.1"` for years of commits, with a manifest comment
explaining that `chia-peer` 0.1.3 was still on `dig-chainsource-interface` 0.1 while chia-query
0.5.2+ had moved to 0.2, so the two `ChainSourceProvider` traits would not unify where the crate
registered its light client into a `ProviderRegistry`. Every sentence of that was true about the
types, and it made the pin look like a real constraint on a real integration. It was not: **nothing
ever constructed that light client.** There was no production `ProviderRegistry` in the crate at
all — the symbol appeared only in the dead module's own `use`, one function signature, and its
`mod tests`. Deleting the module dropped `chia-peer`, `chia-query` and `dig-chainsource-interface`
from dig-node-core outright and collapsed the lock's two `chia-query` lines to one.

The general lesson: before treating a version pin as a constraint, check that the code it protects
has a caller. A pin defended by an articulate comment reads as more load-bearing than one with no
comment, which is precisely backwards when the comment describes an integration that was never
wired. Verify a blocker against the resolved lock and a reference search, never against the note
explaining it — a wrong blocker is worse than none, because it stops people looking.

## The `dig.fetchRange` peer-serve arm was the MISSING half of the chain-anchor invariant (#1764/#1765)

The #127 fail-closed anchor pin was enforced on the read paths (`/s` HTTP tier, `dig.getContent`) but
`dig.fetchRange` — the PEER-SERVE arm a remote peer hits — had NO anchor gate: it validated shape then
served any range that Merkle-verified against the CLIENT-named root. So a permissionless peer could
fetch ranges of a forged or superseded generation that every local read path already refused (`-32005`),
the serve side answering where the read side fails closed (#1765: "no leg serves where another refuses").
The fix hoists the pin into ONE shared `resolve_enforced_pin` (dig_rpc/dispatch.rs) applied to
getContent AND fetchRange, gating BEFORE `fetch_range_frame`, so unanchored content (`Ok(None)`), a
chain error, and a superseded client root all fail closed with `-32005` uniformly across all three paths.

Sharp edge — `x-dig-source` ⊥ `x-dig-verified`: `source` (local|peer|rpc) reports the serving TIER;
`verified` reports only whether the bytes were bound to the chain-anchored root. `verified` is computed
ONCE (`= pin_enforced()`) and threaded identically to the local/peer/rpc `Served` constructions, so a
peer/gateway serve is still `verified:true` under the default pin (the reader re-binds to the anchor);
`verified:false` appears ONLY under `DIG_NODE_PIN=off`, and then on every leg equally.

## PublicManifest (§13) is NOT committed into the current_root — older-gen reads bind via `sha256_latest` (#2088)

A >1-generation store was unreadable for every file NOT in its latest commit: the serve pinned every
read to the chain-anchored TIP root, but a file unchanged since an earlier commit lives in an OLDER
capsule (its own root ≠ tip), so the tip fetch folded to a decoy and the file read as a 404 for every
generation but the latest. The fix reads the tip capsule's embedded `PublicManifest` (§13) to resolve,
per path, the `latest_root` that actually holds the file (`serve_root`) and its `sha256_latest` leaf,
then serves from `serve_root` while requiring `proof.leaf == sha256_latest`.

Sharp edge — WHY the leaf binding is load-bearing and NOT a new trust boundary: the PublicManifest
section is NOT committed into `current_root` (it is additive `.dig` data, `pipeline.rs:83`), and an
older capsule's own root is NOT chain-anchored (attacker-choosable in isolation — the #127 pin would
refuse it from a client). So a proof that merely folds to the older root proves nothing. The read path
binds older-generation bytes to the tip via `sha256_latest`, which is read FROM the tip capsule the
chain vouches for — extending the EXISTING tip-capsule trust, not opening a new boundary. A
client-supplied superseded root still fails `-32005` (anti-rollback preserved); only the node's own
trusted tip manifest may redirect a read to an older capsule.

## §13 lineage cross-check is NOT enough — serve TIP-AUTHORITATIVE to close the Case-A downgrade (#2211)

The #2088 leaf binding + the #184 lineage cross-check together bind a redirected serve to *a genuine
lineage generation*, but NOT to the path's *canonical/maximal* one — because `latest_root` is read
from the §13 `PublicManifest`, which is additive and NOT committed into the chain-anchored
`current_root`. A malicious holder can serve a genuine, anchor-passing TIP capsule whose §13 is forged
to redirect a path at a genuine-but-SUPERSEDED prior generation (a real lineage root, so the cross-
check honours it) — a downgrade bounded to owner-committed content.

Case A (a path whose CURRENT bytes the tip's own `current_root` commits) is closed at the serve tier:
serve TIP-FIRST with NO §13 leaf binding — bind purely by `proof.root == tip` (the pre-#2088 path) —
and consult the §13 redirect + `expected_leaf` ONLY on a genuine tip MISS (the tip capsule folds the
older-generation file to its constant-time decoy). A tip-committed path is served from the chain-
anchored tip, so a forged redirect is never reached; a legitimately-older-generation file misses at
the tip and falls through to the (still §13-driven, still lineage-authenticated) redirect exactly as
#2088 intends. Sharp edge: `current_root = MerkleTree::from_leaves(merkle_leaves)` commits ONLY the
tip generation's own leaves (digstore `data_section.rs`), which is WHY a tip-committed path is present
at the tip and an unchanged-since-older-gen path is absent — the whole tip-first split rests on it.

Case B (a path whose current version genuinely lives in an OLDER generation than a forged §13 names)
stays OPEN on #2211, blocked on the per-path current-state commitment the tip must anchor (digstore
#2203). `expected_leaf` proves the served bytes are *a* genuine lineage generation, not that it is the
path's canonical current one.

## The tip-authoritative Case-A closure rests on an ENFORCED premise, not an assumed one (#2211)

The Case-A closure above assumes "a tip serve MISS for a path means the path is legitimately absent
from the tip generation → consult the §13 redirect". That premise holds ONLY if the tip capsule
genuinely HOLDS every leaf its `current_root` commits. It is NOT free: the capsule anchor gate
(`module_anchor.rs`, `ChainAnchoredModuleVerifier`) compares only the 32-byte `CurrentRoot` HEADER
against the chain — it NEVER recomputes the tree from `MerkleNodes`. So a single malicious holder can
craft a tip `.dig` whose `CurrentRoot` header still equals the genuine chain tip (a lie) while its
data is tampered so a tip-committed path no longer folds to it; the honest node admits + caches it,
the tip serve MISSES that path, and the forged §13 drives the redirect → the rollback the Case-A fix
was supposed to prevent. (Proven: with the redirect gate disabled the read serves `V1-OLD`.)

Fix: before trusting a §13 redirect to move a read OFF the tip, re-derive the tip capsule and require
its data to fold to its committed tip — `digstore_compiler::verify_module_root` recomputes the merkle
root from the capsule's own `MerkleNodes` and checks it equals the committed `CurrentRoot`, plus that
root must equal the chain-anchored tip. A tampered tip fails this → the redirect is refused → clean
miss, never a downgrade. Placed at the §13-trust boundary (not the anchor gate) so it covers a tip
capsule however it entered the cache, and costs a whole-module read only on the redirect-candidate path.

Sharp edge — the two-pass serve must DEFER a tip-pass upstream error. Reordering the serve to tip-first
then §13-redirect meant a Tier-3 upstream ERROR in the tip pass returned `Some(Unreadable)` and
short-circuited before the redirect pass — regressing #2088 (a legitimately-older-generation file
dead-ended as `Unreadable` whenever an upstream was configured). A non-Served tip outcome (decoy miss
OR upstream error) must NOT be treated as definitive while a §13 redirect candidate remains: hold it,
try the redirect, and only surface the tip pass's own `Unreadable`/`NotFound` if the redirect also
misses.

## §21 backfill and the #1576 reshare are TWO transports for the same capsule — one gate, not two (#1614)

A read miss can pull the SAME `(store, root)` whole `.dig` down two independent legs, and for a long
time each had its OWN in-flight set, blind to the other:

- **Leg A — §21 backfill** (`maybe_backfill_capsule` → `gap_fill_generation` → `cache_fetch_and_cache`):
  the authenticated whole-store sync from the RPC upstream. This is the PEERLESS-network fallback — it
  can acquire a capsule when NO peer serves it, so it must never be suppressed away.
- **Leg B — #1576 reshare warm** (`spawn_capsule_reshare` → `CapsuleWarmer::warm`): the P2P pull that
  makes a reader a discoverable HOLDER. It has NO upstream fallback — with no providers it just refuses.

Because Leg A used `Node::backfilling` (a `HashSet<String>`) and Leg B used a separate `WarmRegistry`,
a single read fired BOTH — 2× bandwidth/disk/CPU for one artifact. The fix is one shared single-flight
gate: `Node::capsule_acquisition` is the ONE `Arc<WarmRegistry>`, and the reshare warmer is wired with a
CLONE of that same Arc (`wire_capsule_reshare(..., node.capsule_acquisition_gate())`), so both legs
test-and-set one registry keyed `"{store}:{root}"`. The keys were ALREADY byte-identical across the two
sites (`CapsuleKey::Display` == `maybe_backfill`'s `format!` == `WarmRegistry`'s key), which is what made
the collapse race-free — one mutex, one key space. Load-bearing ordering: each leg's origin/config/held
gates run BEFORE it claims the gate, so a gated-out read (a Peer origin, a cross-site read, an already-held
capsule) never consumes a slot. Keep BOTH legs — dropping Leg A would lose the peerless fallback.

## Root has NO systemd `--user` bus, so a user-scope service install is impossible under `sudo` (#526)

`systemctl --user` (and everything `service-manager`'s systemd backend does at `ServiceLevel::User`)
talks to a **per-login-session D-Bus user manager**. A process running as root under `sudo` inherits
the invoking user's environment but NOT their session bus, and root's own user manager is normally not
running, so the call fails with `Failed to connect to bus: Operation not permitted` — surfacing to a
caller as a bare non-zero exit (the dig-installer observed `exited with 6`). There is no environment
tweak that makes this work in general: `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` point at the
*invoking* user's runtime dir, which root may reach but which registers the unit for THAT user's
session — not a machine-wide service.

Two consequences that generalize beyond this repo:

- **An elevated installer must register SYSTEM scope, not user scope.** A user-scope unit only starts
  when its user's session/manager starts, so on a headless host it may never come back after a reboot.
  Only a system unit (`WantedBy=multi-user.target`) starts at boot with no login session — which is why
  dig-node's own `.deb`/`.pkg` always registered system scope while the CLI's `install` verb did not.
- **The privilege level, not the platform, decides the default.** A single compile-time "prefer user
  level" constant cannot express it: the same binary on the same OS must land a user unit for a desktop
  double-click and a system unit under `sudo`. The scope has to be a RUNTIME value (see `resolve_scope`
  in `crates/dig-node-service/src/service.rs`) — and, because both scopes can be registered
  independently, an install at one scope must clear the other or two units race for the node's port.

## A git-pinned peer-stack dep hides shipped fixes indefinitely — the network looked dead for 11 minors (#1771)

dig-gossip is a **git dependency pinned by rev** (it cannot go to crates.io until dig-peer-protocol
#681 lands), so it does not participate in any automated dependency cascade: nothing bumps it, and
`cargo update` will not move it. It sat at a v0.16.0-era rev while eleven minors accumulated upstream,
including all THREE duplicate-connection fixes (#1691 inbound, #1703 `connect_to`, #1762
`adopt_nat_connection`). A live EC2 run reproduced all three symptoms *simultaneously* — the fixes were
real, released, tested, and simply not present in the binary. **A rev-pinned dep needs a deliberate,
scheduled bump; treat "the fix is released" as unproven until the pin says so.**

Two couplings make that bump non-trivial, and both are structural rather than incidental:

- **The peer stack's dig-nat major moves as ONE atomic step.** dig-node-core constructs its own
  `NodeCert` / `NatConfig` / `NatRuntime` / `RelayStatus` / `TraversalKind` values and passes them INTO
  dig-download, dig-gossip and dig-peer-selector. Two dig-nat instances in the tree therefore do not
  merely bloat it — those calls stop typechecking (`E0308 expected dig_nat::relay::RelayStatus, found
  dig_nat::RelayStatus`). So bumping dig-gossip across a dig-nat major forces dig-nat + dig-dht +
  dig-download + dig-peer + dig-peer-selector in the same commit, and it is blocked outright until every
  member of the line is published. `tests/dependency_tree.rs` asserts the single-instance invariant
  against the resolved lock, which is what makes a partial cascade fail loudly instead of oddly.
- **The vendored-fork patch revs move in lockstep with the dep rev (the #1529 3-rev rule).** A git
  dep's own `[patch.crates-io]` does NOT apply transitively, so the workspace re-declares dig-gossip's
  vendored additive `chia-protocol`/`chia-sdk-client` at the SAME rev. Leaving the patch rev behind
  resolves two copies of a patched crate — a tree that builds green and behaves oddly.

**The behavioural half of a bump matters more than the compile half.** The v0.17 pool republishes
`PoolEvent::PeerAdded` when a fresh session supersedes a stale slot for the same `peer_id`, so any
consumer that counts `PeerAdded` events over-counts under reconnect churn — all of dig-node's consumers
are keyed by `peer_id` and idempotent, so they were safe, but the download-side connected pool APPENDED
the new address and left the superseded (typically dead) one leading the dial order, costing a failed
dial per fetch. Likewise `GossipStats::total_connections` is a LIFETIME counter a supersede increments;
only `connected_peers` / `pool_stats().connected` (live keyed-map sizes) are unique-peer counts. When
bumping a dep whose fix removes a REFUSAL, audit what the refusal was silently keeping rare.

## A mock-transport regression test proves NOTHING about the wire — the read leg died in JSON serde (#1586)

`dig.fetchRange` frames are JSON, so the ciphertext window travels as **base64** — the canonical
`dig_rpc_protocol::types::RangeFrame` says so ("this window's ciphertext, base64") and the node's own
`fetch_range_frame` emits exactly that. dig-nat's `RangeFrame` (< 0.11.2) read the same field with
`#[serde(with = "serde_bytes")]`, which over JSON takes a string as its LITERAL UTF-8 characters. So a
served 1-byte window arrived as the 4 characters of `"AA=="`, `assemble_range_stream` rejected it as
"range frame overflows expected length 1", and the download aborted. Two traps compounded it:

- **The error text lied.** dig-download's `establish_commitment` (the 1-byte meta-probe that seeds the
  chunk layout) returns `DownloadError::NotFound`, whose Display read *"no providers located for
  `content id`"* — identical to a genuinely empty locate. Four investigations chased a
  provider-key mismatch that did not exist; the locate had in fact returned the holder and the
  connected-pool confirm-bypass had fired. Ordering in the log was the tell: a `fetch_range` line
  BEFORE the "no providers" line can only come from the probe, which runs *after* a non-empty locate.
  (dig-download >= 0.7.2 now names the failing step.)
- **Every prior regression test asserted at a MOCK `RangeTransport`.** The mocks return a
  `FetchedRange` struct directly, so the whole wire — serde, framing, mTLS, dig-peer — was unexercised
  and green while production could not read a byte. A read-leg test is only meaningful if it asserts a
  `dig.fetchRange` RPC was **received by a real holder**;
  `connected_pool_holder_receives_a_real_fetch_range_rpc_over_mtls` (dig-node-core `download.rs`) does
  that over a loopback mTLS `serve_peer_rpc_listener`, which is cheap and needs no EC2.

Rule of thumb: a cross-repo wire contract needs a CONFORMANCE test that pins the actual serialized
shape (dig-nat `tests/wire_conformance.rs`), plus at least one test that puts real bytes on a real
socket. Type-level agreement across two crates is not wire agreement.

**A consumer's `Cargo.lock` can silently re-pin an old patch of a TRANSITIVE dep even after you bump
it elsewhere.** Bumping dig-node's own `dig-nat` requirement to 0.11.2 did NOT put the fix on the
`fetchRange` path, because the decode actually runs inside `dig-download`'s `NatRangeTransport`, and
dig-download's OWN `Cargo.lock` — resolved independently at dig-download's last release — still
pinned `dig-nat 0.11.0`. dig-node's caret dep on `dig-download = "0.7"` was satisfied by 0.7.1, which
carried the stale transitive lock forward untouched; `cargo update -p dig-nat` at the dig-node level
does nothing for a dep dig-download links in from ITS OWN lockfile-pinned graph position once
dig-download itself isn't rebuilt/republished. The fix required bumping dig-download to 0.7.2 (a
release that itself picked up dig-nat 0.11.2), THEN `cargo update -p dig-download --precise 0.7.2` in
dig-node. **Lesson: when a fix lives N layers down a dependency chain, verify the FIRST direct
dependency's OWN lockfile carries the fix — a same-repo, direct-dep-only bump can leave the actual
decode path on the old code for iterations.**

## The fetch transport dials ONE address — `best_address()`, the FIRST dialable — so union ORDER, not just the merge, decides reachability (#836/#1590)

Merging same-peer address hints across discovery sources is necessary but NOT sufficient. The real content
transport does not try every advertised address: `NatRangeTransport::provider_to_target` (dig-download
`source.rs`) dials the SINGLE `provider.best_address()`, and dig-dht `record.rs` defines `best_address()` as
"the FIRST candidate whose kind `is_dialable()`" (Direct/Mapped/Reflexive; Relay is not dialable) in LIST
ORDER — `addresses` is not re-sorted at merge time (`UnionLocator::sanitize_address_hints` dedups+caps but
does NOT sort). So the address that WINS the dial is whichever source's hint LEADS the merged list.

The download union merges same-peer_id records onto the FIRST-SEEN record (`existing.addresses.extend(...)`),
so the first-queried source leads. With the DHT source first and the pool second, a stale/unreachable DHT
hint (e.g. `172.31.44.121`, or a relayed-net address the reader cannot dial) leads the list and becomes
`best_address()`, so every confirm/fetchRange dial hits the unreachable address and the read 404s — even
though the reachable pool address (`:9444`) is present in the record, just later. Fix: put the
`PoolProviderLocator` FIRST in the DOWNLOAD union (`NodeContent::new`) — a pool entry is a LIVE,
connection-verified address, strictly better than an untrusted advertised DHT hint — so it leads the list
and `best_address()` selects the address that actually connects. This orders ONLY the download union; the
DISCOVERY leg (`self.locator`, find_providers/redirect) is untouched, and the #1584 self-exclusion,
#1580 capsule-fallback, and verify-then-decrypt fail-closed all still compose.

Test gotcha — model `best_address()`, NOT `.any()`: a mock transport whose `is_reachable` checks
`addresses.iter().any(|a| a == reachable)` FALSE-GREENS this bug. `.any()` passes whenever the reachable
address is present ANYWHERE in the list, so it "passes" even under the broken append-order where the
unreachable hint leads. The faithful model is `addresses.iter().find(|a| a.kind.is_dialable())` (the exact
`best_address()` rule) — that test is RED under the old order (best_address = unreachable) and only GREEN
once the reachable address leads. Any test that predicts this read-leg e2e MUST model the single-address
`best_address()` dial, or it silently green-lights a still-broken dial path.

## Self-exclusion is per-PATH: the DISCOVERY leg and the FETCH-DIAL candidate set are SEPARATE (#1584 vs #836/#92)

"The reader must never fetch from itself" has to be enforced on EVERY path that produces a dial candidate,
not once. #1584 self-excluded the gossip pool AND the raw DISCOVERY locator (`SelfExcludingLocator` around
the dig-dht union, plus `NodeContent::find_providers`), but the DOWNLOAD locator is a DIFFERENT set: it
UNIONs that discovery locator with a `PoolProviderLocator` over the connected pool — and that pool branch
was NOT self-excluded. A relay-introduced self-connection (the relay introduces the reader to itself)
surfaces this node in its own gossip pool (`peer_id == local`), the pool feed mirrors it into the
connected-pool map, and the un-excluded `PoolProviderLocator` then offers SELF as a fetch candidate.

Symptom (run e2e-836-arb-20260725-084501): the fetch dials the reader's OWN reflexive addr at an ephemeral
port (`Direct → own IP → Connection refused`) and the relayed fallback logs `refusing relayed self-dial
(target == local peer_id)`; the confirm round is starved, so dig-download reports `no providers located`
for the resource and the read 404s — EVEN THOUGH the real holder is connected at `:9444` and the pool
locator correctly offered it. Both the self-dial AND the "no providers located" share ONE root: the
self entry poisons the confirm so it never completes against the holder.

Fix = two defenses: (1) drop a self `PeerAdded` at the pool feed (`on_pool_event`) so self never enters the
connected pool OR the selector registry; (2) wrap the WHOLE download locator in `SelfExcludingLocator` so
no source — DHT or pool — can offer self on the fetch/dial path. Gotcha for future work: any NEW locator
unioned into the fetch/download path is a new instance of this class — self-exclude it at the point it is
composed, and TEST it with a target-RECORDING transport (a mock that serves bytes regardless of dial target
cannot tell a holder-dial from a self-dial and will falsely pass).

## UnionLocator dedup-by-peer_id was DROPPING a reachable address, not just a duplicate record (#1590/#836)

The download locator unions two provider sources that can name the SAME authenticated peer_id with
DIFFERENT addresses: the raw DHT discovery locator (a peer's *advertised* provider record — an untrusted,
often stale/relayed-net reach hint) and the `PoolProviderLocator` (the peer's *live connection* address,
connection-verified and reachable). `UnionLocator` deduped by `peer_id` keeping the FIRST-SEEN record whole
and DISCARDING every later same-peer record — so the DHT's UNREACHABLE hint (seen first) SHADOWED the pool's
REACHABLE address for the same holder. The confirm/fetch then dialed only the unreachable address, every
dial refused, dig-download reported `no providers located for ContentId::Resource {…}`, and the read fell
through to §21 upstream → DATA 404 — even though the reader was CONNECTED to a dialable holder.

Symptom (arbiter e2e c0954369, run e2e-836-arb-20260725-094734): `fetch_resource: located providers before
download … located=1 connected_pool=1` and the pool locator logs it is offering the holder at `:9444`, yet
the fetch still fails with `no providers located for the resource` and dials a DIFFERENT, refused address
(`172.31.44.121:<ephemeral>`) — the DHT hint — instead of the pool's `172.31.29.67:9444`. The tell is that
locate found "1" but the fetch dialed an address the pool never offered.

Fix = `UnionLocator` now MERGES the (untrusted, `MAX_ADDRS_PER_PROVIDER`-capped) address hints of same-peer
records across sources instead of dropping the later record. peer_id stays the authenticated identity
(SPKI-pinned at connect); addresses are only reach hints, so unioning them is safe, and the reachable pool
address survives so a `fetchRange` reaches the holder. First-seen record ORDER is preserved (dig-dht stays
authoritative for ordering; this is a no-op on the DISCOVERY union `[dht, empty, empty]`, so redirect hints
stay capsule/announced-holder granularity — unpolluted).

Gotcha for future work: a peer_id-keyed dedup across sources that each contribute their own ADDRESS hints
must MERGE addresses, never keep-first-drop-rest — otherwise the "best" (reachable/verified) address can be
lost purely because a worse source named the peer first. Test it with an ADDRESS-aware transport (fail the
dial unless the record carries the reachable address); a peer_id-only mock cannot catch this.

## Gossip-vs-peer-RPC port confusion is a recurring bug CLASS across pool-consuming feeds (#1575, #1590/#836)

The dig-gossip connected pool reports each peer's GOSSIP endpoint (`:9445`, `DEFAULT_GOSSIP_PORT`), but
every service dialed for content/routing lives on the peer-RPC endpoint (`:9444`, `DIG_PEER_PORT`) — the
two listeners co-locate at a fixed offset of 1 (`GOSSIP_TO_DHT_PORT_OFFSET`). Any code that takes a pool /
`PoolEvent` address and DIALS it MUST translate `9445 → 9444` via `dht_addr_from_gossip_addr` first; a raw
gossip addr dials the GOSSIP listener for a peer-RPC/`dig.fetchRange` stream and dies with
`received corrupt message InvalidContentType` — a SILENT failure (best-effort feeds swallow it), so the
symptom is a downstream 404, not an error at the dial site.

This bit TWICE: #1575 fixed it for the DHT routing feed (`spawn_dht_routing_feed`); #1590/#836 was the
SAME bug recurring in the selector-registry / connected-pool feed (`spawn_selector_registry_feed` →
`PoolProviderLocator`), which fed raw `:9445` addrs into the download-side connected pool, so Tier-2
`fetchRange` dialed `:9445` and every read 404'd despite a connected holder. Fix pattern (both feeds):
translate at the gossip BOUNDARY (the feed), keep `on_pool_event` / the locator addr-agnostic. Gotcha for
future work: a NEW consumer of a gossip/pool address is a new instance of this class — port-translate on
sight. The trap that hid it for six iterations: the fetch path (`peer_serve_plaintext`/`fetch_resource`)
and the pool locator emitted ZERO tracing, so a live-but-misdialing path looked like "never invoked";
they now log the located provider count + the chosen dial target INCLUDING PORT.

## Resource reads locate by resource id, but inventory is announced only at capsule granularity (#1580)

Inventory is announced into the DHT at STORE + CAPSULE (`store_id:root`) granularity ONLY —
`dht::inventory_content_ids` deliberately does NOT announce per-resource records (a capsule holder serves
every resource in it, so per-resource records would be redundant and explode DHT write volume). But a
`/s` resource read miss builds a `ContentId::Resource` and dig-download's discover step
(`locate_and_confirm`) locates providers by that EXACT key. So even after DISCOVER was fixed (#1574/#1575),
DATA still 404'd: `find_providers(resource_id)` found nobody, Tier-2 peer fetch gave up, and the read
dead-ended at the §21 whole-capsule backfill / public RPC — the holder never saw an inbound `fetchRange`.
The serve-path tier ORDERING was already correct (Tier-2 peer runs before Tier-3 RPC); the fault was the
announce-vs-locate granularity mismatch, not ordering.

Fix: `CapsuleFallbackLocator` wraps the content engine's locator so a `ContentId::Resource` lookup ALSO
queries the parent `ContentId::capsule(store_id, root)` and unions the holders. dig-download then confirms
the specific resource against that holder via `dig.getAvailability` + `dig.fetchRange`. No dig-download /
dig-dht API change — the bridge is pure dig-node. Gotcha for future work: anything that locates by a
resource-granularity content id must apply the same capsule fallback, or announce resource granularity
(the latter is intentionally avoided).

## The read-leg 404 after DISCOVER is a FETCH-LEG TRANSPORT fault, not serve routing (#1586/#836)

After #1584 (self-dial) + #1580 (capsule-fallback locate) + #1574/#1575 (live DHT routing), the #836 e2e
still 404'd on DATA: reader CONNECTs (Direct :9444/:9445 + relay) and DISCOVERs the holder
(`getAvailability providers_count=1`), but the holder logs ZERO inbound `fetchRange` and the read
dead-ends at the §21 upstream (`rpc.dig.net` 400 on an isolated net) → 404.

Root-caused by ELIMINATION, not by guessing at the cited `capsule_store.rs` backfill:
- The loopback `/s` serve path (`serve_content_plaintext`) tier ordering is CORRECT — Tier-2 peer fetch
  runs BEFORE Tier-3 RPC, and it verify-then-decrypts fail-closed. Locked by the regression test
  `tests::serve_content_plaintext_fetches_from_peer_when_upstream_unreachable`: with an UNREACHABLE
  upstream + a provider holding a sealed resource, the serve returns `ServeSource::Peer` (it does today,
  via the mock engine). So the fault is NOT the serve routing the issue hypothesized.
- `CapsuleFallbackLocator` (#1580) IS wired into BOTH the enrichment `find_providers` AND the Downloader's
  own locator (`for_dht` builds ONE `CapsuleFallbackLocator` and `NodeContent::new` clones it into the
  Downloader), so LOCATE resolves the capsule-granularity holder for a resource-id read. Not the fault.
- What is left is the FETCH LEG: `NatRangeTransport` (dig-download, over dig-nat via the shared
  `NatRuntime`) dials the located holder to confirm + `fetchRange`. The holder never sees the request, so
  the dial/handshake to the holder fails BEFORE any range is requested.

Leading cause (evidence: this log's #1532/#1541 entries): the dig-nat / DigPeer NAT-traversal transport
still mints a RANDOM EPHEMERAL cert (`nat_node_cert`, dig-gossip `state.rs`), so the holder's NAT-leg
listener presents a `peer_id` that does NOT match its advertised NodeCert `peer_id`. The fetch dial
expects the advertised `peer_id` and fails CLOSED on the mismatch — exactly the #1532 gossip bug, but on
the fetch transport (tracked as #1541, dig-gossip release-first, still open). #1532 unified only the
CHIA-SSL :9444/:9445 listeners; the NAT-traversal identity used by the range-fetch leg is still ephemeral.

Two remediation shapes (orchestrator's release-first call): (a) land #1541 in dig-gossip so the NAT
transport presents the NodeCert (fixes the fetch handshake at the root); or (b) an MVP-green dig-node
bypass — issue `dig.fetchRange` DIRECTLY over the EXISTING connected mTLS peer-RPC session to :9444 (the
one that already succeeded for CONNECT/DISCOVER), skipping the separate dig-nat re-dial entirely. (b) is a
new in-dig-node client path (enumerate connected pool peers that are providers → open a stream on the live
session → `dig.fetchRange` → verify-then-decrypt) and needs a mockable peer-RPC seam to test. Confirm the
peer_id-mismatch hypothesis first from the e2e handshake logs before choosing.

## Runtime capsule GAIN must announce, or the holder is invisible to find_providers (#1586/#1423)

A pinned/backfilled capsule that lands on disk at runtime (a hosted pin via `control.rs`, the read-side
backfill-cache, chain-watch gap-fill, or the `CacheFetchAndCache` RPC) is USELESS to the network unless the
node also re-announces its DHT inventory — otherwise `find_providers` never learns this node holds it, and
a hosted-pin capsule 404'd even though it was sitting on disk. Every one of those landing paths ultimately
calls `CapsuleStore::cache_fetch_and_cache`, so the fix centralizes the re-announce there (fire once on a
FRESH land; an already-cached hit is a no-op) instead of scattering `refresh_dht_inventory` calls at each
call site — `gap_fill_generation` and the `CacheFetchAndCache` RPC handler both had their own explicit
(redundant, idempotent-but-dead) refresh calls, now removed. This is the reshare/flywheel discoverability
invariant (#1423/#1425): every runtime capsule-gain, from ANY path, must make the node a discoverable
holder — the fix generalizes past the single hosted-pin bug by centralizing at the one shared choke point
rather than patching each caller.

## DHT routing is seeded LIVE from gossip PoolEvents, not just the pre-connect bootstrap (#1574)

`bring_up_dht` seeds the dig-dht routing table with a ONE-SHOT `service.bootstrap(bootstrap_peers_from_pool(...))`
— but that call runs BEFORE any peer connects (the pool is empty at bring-up in a freshly-formed
network). dig-dht `find_providers` has no OTHER live source in a new network (PEX/relay-introducer are
dormant EmptyLocators, republish/refresh are on ~1-hour cadences), so routing stayed empty and cross-node
DISCOVER was impossible: a holder could ingest + serve + merkle-verify its OWN capsule and connect fine
(direct + relay), yet a reader's `find_providers` returned empty (holder `capsule_count:1`, reader finds
nobody). The gossip `PoolEvent::PeerAdded`/`PeerRemoved` stream was consumed by the peer-selector
(`spawn_selector_registry_feed`) and PEX, but NOTHING fed it into dig-dht routing.

Fix: `spawn_dht_routing_feed` mirrors the selector feed's shape (seed snapshot -> subscribe -> forward
churn) but drives the DHT routing table — `PeerAdded` -> `DhtHandle::add_peer` (insert), `PeerRemoved` ->
`remove_peer` (evict). This needed a NEW live dig-dht API (`DhtService::add_peer`/`remove_peer`, dig-dht
0.5.2) because `bootstrap` is network-bound + one-shot; the new methods insert/evict a single contact
with no round-trip. Both the ANNOUNCE (holder PUT) and FIND legs traverse dig-dht routing, so both are
fixed by populating it. Lesson: any live peer-membership signal that must reach a subsystem needs its OWN
`PoolEvent` consumer — a pre-connect snapshot is not enough for a network that forms after bring-up.

## The node's chia-ssl listeners share ONE mTLS identity — the gossip pool MUST reuse the NodeCert (#1532)

The node has two in-process **chia-ssl** TLS listeners: the peer-RPC server (:9444) and the dig-gossip
DIRECT connected pool (:9445). The advertised/registered/pinned `peer_id`
(`peer_id = SHA-256(TLS SPKI DER)`) comes from the persistent CA-signed `NodeCert` under
`node_cert_dir()` (`peer-net/identity/node.crt`+`.key`). dig-gossip's `GossipConfig` loads its listener
cert from `cert_path`/`key_path` via `dig_peer_protocol::load_ssl_cert`, and if those files are absent
it mints its OWN throwaway `ChiaCertificate` — a DIFFERENT SPKI → a DIFFERENT `peer_id`. Pointing the
pool at its own `peer-net/node.cert` (the original wiring) therefore made the pool listener present an
identity that did NOT match the advertised one, so a DIRECT dial failed CLOSED with
`peer_id mismatch: expected <advertised>, got <gossip-cert>` — even though a dial-by-address (Leg A)
still "worked" because it accepted whatever cert the listener presented. The fix (`gossip_identity_paths`)
points `cfg.cert_path`/`cfg.key_path` at the NodeCert files themselves (dig-gossip only READS them, so
it can never clobber them) and sets `cfg.peer_id` from the SAME SPKI via
`dig_gossip::peer_id_from_tls_spki_der(identity.spki_der())`. RULE: any new chia-ssl node listener
presents the NodeCert; never let a sub-component mint its own transport identity. Regression:
`peer::tests::gossip_listener_presents_the_advertised_peer_id`.

SCOPE (important, #1532 vs #1541): this unifies the CHIA-SSL path (:9444 + :9445 direct-gossip) ONLY.
The dig-nat / DigPeer NAT-traversal transport is SEPARATE: dig-gossip's `nat_node_cert`
(`state.rs:643-654`) still mints a RANDOM EPHEMERAL cert, and `pex.rs:625/630` dials over dig-nat — so
the RELAYED + hole-punch tiers still present an ephemeral peer_id. Unifying that NAT-traversal identity
with the persistent NodeCert is tracked SEPARATELY as #1541 (Defect 1b, dig-gossip release-first). Do
NOT claim "every listener" / full identity unification until #1541 lands.

## digstore git-rev pins must move in LOCKSTEP across ALL crates (read-root hardening #1439/#1473)

The digstore-* git deps are pinned by `rev` in FOUR crate manifests, not just the two obvious ones:
`dig-node-core` (7 deps), `dig-node-service` (3, a test fixture), `dig-runtime` (1), and `dig-wallet`
(2). They share ONE workspace `Cargo.lock`, so a partial bump leaves the lock resolving two revs of
the same git source — two incompatible copies of `digstore-core` (its `Bytes32` from crate A ≠ from
crate B) that fail to unify at crate boundaries. When bumping the digstore rev, `grep -rn 'rev =
"<old>"' crates/` and move EVERY occurrence together, then let `cargo test`/`cargo check` re-resolve
the lock (there is no single `cargo update -p digstore-core` — the spec is ambiguous because a
crates.io `digstore-core 0.13.4` also lives in the tree via a separate dep path; leave that one).

The #1473 hardening (`verify_pinned_root` anchoring identity on the unforgeable launcher coin,
`coin_id == store_id`, via a bounded backward `parent_coin_info` coin-record walk instead of the
forgeable curried `SingletonStruct.launcher_id`) shipped as a pure internal rewrite: the public
signature `verify_pinned_root(&dyn ChainReads, store_id, pinned_root)` is UNCHANGED between d5e52fb
and 4c34f0be, and `Coinset` already implements the `coin_record`/`coin_spend` `ChainReads` methods
the new walk needs — so the dig-node call site (`CoinsetResolver::verify_pinned_root`) needed ZERO
code change. Deep forge-rejection coverage lives in digstore's `golden_read_proof.rs`; the node layer
only guards the fail-closed wiring.

## A `Get-Acl` readback in the security hot path fails on hosts that can't autoload the PS Security module (#849/#856)

The #501 control-token state-dir hardening READBACK-VERIFIED the DACL by spawning `powershell
Get-Acl`. `Get-Acl` lives in `Microsoft.PowerShell.Security`; on a host where PowerShell cannot
autoload that module the cmdlet THROWS, the spawn exits non-zero, and `windows_harden_dir` read
that as a hardening FAILURE → `remove_dir_all` (fail closed) → the LocalSystem service then had no
state dir to mint the control token into → every `dign`/`control.*` call failed UNAUTHORIZED. On a
pristine box (working PS) it worked, so it looked machine-specific rather than a universal bug.

Durable lessons:
- Read Windows ACLs/owners through the Win32 security API (`GetNamedSecurityInfoW` for owner + DACL,
  `GetAce`, `ConvertSidToStringSidW`), NEVER a PowerShell/`Get-Acl` spawn: no module-autoload
  dependency, no shell, no localized-name parsing, no LPE via a planted `powershell.exe` in the
  application dir (the #565 second-order lesson). `windows-sys` already ships these; `security.rs`
  centralizes them (`read_owner_sid_string`, `read_acl_verify_lines`). Standard allowed/denied ACE
  trustee SIDs sit at the fixed `SidStart` offset (header 4 + mask 4 = 8) from the ACE pointer.
- A DEFENSE-IN-DEPTH readback must NOT be able to destroy the thing it verifies. Distinguish
  "read the ACL and it VIOLATES policy" (fail closed — remove + regenerate) from "could NOT read
  the ACL at all" (the SET commands already succeeded → trust the applied lockdown, preserve the
  dir). Conflating the two turns any readback-tool hiccup into data loss + a broken control plane.

## The node emitted tracing into the void — no subscriber was ever installed (#553)

`dig-node-core` and its P2P/TLS stack emit `tracing` events, but `dig-node-service` installed NO
`tracing-subscriber`, so every event was silently DROPPED and a Windows-service run (no console)
produced no log at all. The fix adopts the shared `dig-logging` crate at the SERVE entrypoints
(the foreground `run`/unix daemon in `entrypoint::block_on_serve`, and the Windows service body in
`win_service::run_service` — one-shot CLI commands deliberately do NOT install it). Sharp edges:

- `tracing` has ONE global subscriber per process, and `dig_logging::LogGuard` is not `Clone` and
  must be HELD for the process lifetime (dropping it flushes/detaches the file writer). So the guard
  lives in a process-global `OnceLock` in `logging.rs` rather than threaded through `serve`'s
  signature + every test caller — that also gives `control.log.setLevel` the reload handle for free.
- Per-request logging (`logging::log_rpc_dispatch`) takes ONLY the method name, never `params` — a
  control/pairing body carries the control/paired token (dig-logging SPEC §7 never-log), so the
  logger's signature makes leaking it impossible. A `tests/never_log.rs` capture test locks this in.
- Windows MAX_PATH: a deeply-nested worktree overflows 260 chars building `libz-sys`/cmake; set
  `CARGO_TARGET_DIR` to a short path (e.g. `C:/t553`) to build/test from such a worktree.

## Bare-git dependency version pins unify across the WHOLE dependency graph, not per-manifest (#494)

A `git`-sourced Cargo dependency with NO `rev`/`branch`/`tag` is identified purely by its URL —
every crate in the build graph that declares `dig-constants = { git = "https://github.com/..." }`
with no ref resolves to the SAME package instance, whatever `version =` requirement each manifest
states individually. If two manifests state incompatible 0.x requirements against that one bare
source (e.g. `dig-node-core`'s transitive `dig-nat`/`dig-gossip`/`dig-dht`/`dig-onion` chain pins
`dig-constants = "0.2"`, i.e. `^0.2` = 0.2.x ONLY), cargo cannot resolve a single version
satisfying both — bumping one manifest's bare-git requirement to `"0.3"` breaks the whole graph
until every bare-git consumer moves together.

**The escape hatch:** an EXPLICIT `rev =` pin is a cargo-DISTINCT source from a bare git dep,
even at the identical commit — so a crate that needs a newer version of a NOT-yet-crates.io'd
dependency can `rev`-pin its OWN copy without forcing every other bare-git consumer forward. This
is exactly how `dig-node-service` picked up `dig_constants::DIG_NODE_PORT` (added in 0.3.0)
without waiting on `dig-nat`/`dig-gossip`/`dig-dht`/`dig-onion` to move off their `^0.2` pin: it
added `dig-constants = { version = "0.3", git = "...", rev = "<v0.3.0 commit>" }`, giving the
crate its own 0.3.0 instance living alongside the graph's existing 0.2.1 (bare-git) and 0.1.0
(crates.io registry) instances. Safe whenever the only thing crossing the boundary between the
two instances is a plain value type (here, a `u16` constant) — never safe if a type from one
instance needs to be passed to/from code built against the other.

## The dig-installer's `install` → `start` sequencing constrains what `dig-node install` may do

`dig-installer`'s `register_dig_node` step calls `dig-node install` and then, when configured to
start it (the default), a SEPARATE `dig-node start` — and treats a `start` FAILURE as fatal for
that installer step (unlike the tolerant treatment of an `install` failure). This means
`dig-node install` must NEVER auto-start the service itself: if it did, the installer's follow-up
`start` would hit "service already running" (Windows SCM 1056, or a systemd/launchd
no-op-or-error depending on backend) and could flip the installer's REPORTED `installed` status
to `false` even though the service is actually up and running fine. `dig-dns`'s equivalent
`reinstall()` DOES auto-start at the end of its clean-reinstall — that pattern was deliberately
NOT mirrored here for this reason. Any future change to `dig-node install`'s start behavior must
also update `dig-installer`'s `register_dig_node`/`install_service` in the SAME unit of work.

## `dign start` is idempotent + the control-token "not found" message can really be an ACL denial (#772)

Two coupled operator-CLI traps, fixed together:

- **`dign start` must treat already-running as SUCCESS.** Windows `sc start` on a running service
  exits non-zero with `[SC] StartService FAILED 1056: An instance of the service is already
  running.` (`service-manager` surfaces that stdout as the `io::Error` message). `service::start`
  now classifies the error text (`service::is_already_running_error`: SCM 1056 / launchd "already
  loaded"/"already in progress" / systemd "already active" — systemd `start` is normally a silent
  no-op) and reports success (`already_running: true`, exit 0). Idempotent start is the contract; a
  running node is the desired end state, not a failure.
- **"no control token found" was mis-reported for an ACL-denied token.** The control token lives at
  `<state_dir>/control-token` and, on a real Windows install, the state dir is locked to
  `{SYSTEM:F, Administrators:F, [install-user:R]}`. If the invoking user is NOT a trustee, they can't
  even STAT the file, so `path.exists()` returns `false` — which made the remedy print the misleading
  "no control token found … start the node" (the NotFound branch) even though the node WAS running
  and HAD minted the token. Classify by the READ error KIND instead (`PermissionDenied` = present but
  locked → "elevate / reinstall"; other = truly absent). The absent-token remedy now also names the
  STALE-service recovery: a service from an older build (pre machine-wide-state-dir) never mints the
  token at this path, so `dig-node uninstall` + an elevated `dig-node install` + `dig-node start`
  (reinstalling the current binary) is the fix. That STALE-service case is the most likely cause of a
  live "service running yet token missing" report on a box that upgraded dig-node in place.

## `service-manager`'s systemd backend registers under `to_script_name()`, not `to_qualified_name()` (#494)

`ServiceLabel` has TWO different string renderings — `to_qualified_name()` (`{qualifier}.
{organization}.{application}`, e.g. `net.dignetwork.dig-node`) and `to_script_name()`
(`{organization}-{application}`, e.g. `dignetwork-dig-node` — the qualifier is DROPPED
entirely). `service-manager` 0.7's Windows (`sc.rs`) and launchd (`launchd.rs`) backends both
register the service under `to_qualified_name()`, but its **systemd** backend (`systemd.rs`)
names the actual unit file from `to_script_name()` instead — a real, silent divergence with no
compile-time signal. Any code that probes "is this service registered?" by shelling out
directly (`service-manager` itself exposes no such query) MUST use the SAME name the relevant
backend actually registered under, per-platform — using `to_qualified_name()` uniformly makes
the probe always report "not found" on Linux, invisibly. This was caught only by a REAL 3-OS
`service-smoke` CI run (mocked-backend unit tests, being backend-agnostic by design, cannot
catch it) — a second `dig-node install` on `ubuntu-latest` reported `reinstalled:false` because
`is_installed()` never saw the service it had just registered.

## Windows `sc create` always names the display the same as the service id

`service-manager` 0.7's `sc.rs` backend hardcodes the Windows SCM display name to the service id
at `sc create` time — there is no `ServiceInstallCtx` field for it. The only way to set a
friendly display name is a POST-create `sc config <id> displayname= "<name>"` follow-up (and,
per #494, a `sc qc <id>` read-back to actually confirm it took, rather than trusting the `sc
config` exit code). `service-manager`'s systemd/launchd backends have no display-name-equivalent
override either — for systemd the closest analog is `Description=`, generated from the label with
no override field; for launchd there is no such key at all. The NATIVE `.deb`/`.pkg`/`.msi`
packages (`packaging/`) sidestep this entirely by shipping their own static unit
file/plist/WiX-`ServiceInstall` with the friendly name baked in — only the bare `dig-node install`
CLI path (not via a native package) needs the `sc config`/`sc qc` dance.

## HTTPS serve on dig.local (#624) — the dig-cert consumer

- The node serves the SAME axum router over TLS on `127.0.0.2:443` (`https://dig.local`) + a
  best-effort `[::1]:443` sibling, beside the kept plaintext `:80` listener. TLS material comes
   from the `dig-cert` crate (pinned git-dep `tag = "v0.1.0"`, NOT `main` — release-first §4.1);
  the config is built via `dig_cert::load_server_config` (a reloadable `ReloadableCertResolver`).
- **Fail-soft is mandatory:** the CA + leaf are provisioned by the installer (#623), which may not
  have run. `crate::tls::load_https_material` returns `None` (⇒ plaintext only) when `leaf.{crt,key}`
  are absent/unloadable — HTTPS is never a hard requirement, mirroring the best-effort `:80` bind.
- **Rotation:** the node is the runtime OWNER but delegates the HOW to dig-cert's `RenewalManager`.
  A daily `maintain` pass re-issues the leaf from `ca.key` at <30d remaining, atomically swaps the
  pair, and fires `resolver.reload()` → the live listener serves the new leaf with no restart. The
  CA anchor is NEVER auto-rotated here (only `ca_renewal_due` is reported; `rotate_ca` is
  installer-coordinated). Only install + renewal read `ca.key`.
- **Gotcha — TLS-serving stack:** reuse `axum-server` (`RustlsConfig::from_config(Arc::new(config))`
  + `from_tcp_rustls(...).handle(handle).serve(...)`), the SAME crate dig-wallet's mTLS listener
  uses. Pin `rustls` 0.23 default-features-off `ring/std/tls12/logging` byte-identical to dig-cert /
  dig-node-core / dig-dns, or a second `CryptoProvider` triggers the install panic.
- **Test gotchas:** (1) an HTTPS integration test that runs the listener as a spawned task AND does a
  synchronous rustls handshake probe MUST use a multi-thread runtime + `spawn_blocking`, else the
  blocking probe starves the server on a current-thread executor → deadlock. (2) A raw rustls client
  that VERIFIES the chain rejects the leaf with `MalformedDnsIdentifier` because webpki refuses the
  `*.dig` single-label wildcard SAN (dig-cert SPEC §3.1) — use an accept-any verifier when the probe
  only needs to CAPTURE the presented leaf; real CA-trust is proven by the reqwest request instead.
- **Windows target-path gotcha:** building the fresh worktree failed compiling `libz-sys` via cmake
  ("link.exe could not be run" / `DirectoryNotFoundException` on a `.tlog`) because the deep
  `modules/.worktrees/dig-node-624/target/...` path trips MSBuild/cmake MAX_PATH — set a short
  `CARGO_TARGET_DIR` (e.g. `C:\dnt624`) to build.
- **Privileged-owner check walks the WHOLE path (#712):** `crate::security::dir_is_privileged` (the
  shared #565/#661/#46 gate) verifies EVERY ancestor component, not just the leaf, and rejects any
  symlink/junction/reparse component — a privileged leaf under a user-writable or symlinked ancestor
  is still swappable (intermediate rename/replace obeys the PARENT's perms; a reparse redirects the
  whole path). Windows gotcha: `C:\Program Files` is owned by `NT SERVICE\TrustedInstaller`
  (fixed SID `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`, byte-identical on
  every host), NOT SYSTEM/Administrators — so the ancestor walk MUST accept that SID or it
  false-rejects the canonical `%ProgramFiles%\DIG\bin` install root. Reparse detection uses the
  no-follow `symlink_metadata` + `FILE_ATTRIBUTE_REPARSE_POINT` (catches junctions, not just
  symlinks). Mirrors dig-dns's `ensure_prefix_root_owned_not_writable` (#701).

- **dig-gossip 0.3.0 needs dig-nat 0.3.0, which the crates.io peer stack blocks (WU5 #929).**
  dig-gossip v0.3.0's code reads `dig_nat::wire::RelayPeerInfo.addresses` — a field that exists ONLY in
  dig-nat 0.3.0 (its `>=0.2,<0.4` req is looser than the code). But dig-dht, dig-download, and
  dig-peer-selector (crates.io 0.1.2 AND their git `main`) still pin dig-nat `^0.2`, and the workspace
  `[patch.crates-io] dig-nat = { git }` can only redirect onto a version those consumers accept — 0.3.0
  does NOT satisfy `^0.2`, so the graph forks into two incompatible dig-nat instances (crates.io 0.2.0
  vs git 0.3.0) and fails to compile (`PeerId`/`Contact` type mismatch at the dht.rs seam). ADOPTION
  ORDER: republish dig-dht + dig-download + dig-peer-selector accepting dig-nat `>=0.2,<0.4` → bump
  dig-nat to 0.3.0 across the graph → then dig-gossip 0.3.0 is consumable (unlocking B1 dialable-fold,
  B2 relay-transport connected-count + `connected_pool_peers_with_via`, and the `Register.listen_addrs`
  advertisement). Until then the node stays on dig-gossip 0.2.1 (`connect_to` + `connected_pool_peers`
  exist there), the per-peer `via` is always `"direct"` (0.2.1 has no relay-transport peer kind), and
  `listen_addrs` is not advertised in the relay Register.

- **Adding a dep here needs a SURGICAL Cargo.lock merge (git-HEAD-drift makes re-resolution
  impossible).** `dig-constants` (bare-git, req `^0.4`) and `dig-nat` (bare-git; dig-gossip pins it
  `>=0.2,<0.4`) have both advanced their default-branch HEAD PAST their constraints (0.5.0 / 0.4.0), and
  bare-git deps expose ONLY the version at HEAD. So ANY resolution that isn't `--locked` — including
  `cargo build`/`cargo update <spec>`/`--offline` after editing a manifest — re-picks HEAD and FAILS to
  select `dig-constants`/`dig-nat`; pinning via `rev=` forks the source (two incompatible copies) and is
  forbidden (the manifest comments say so). CI only ever runs `--locked`. To ADD a new dependency without
  the deferred `^0.5`/dig-nat cascade: resolve the NEW deps ALONE in a throwaway crate (same
  `[patch.crates-io]` chia-protocol/chia-sdk-client pins) → `cargo generate-lockfile` → diff its lock vs
  the repo's → hand-insert ONLY the genuinely-new package NAMES' `[[package]]` blocks (shared crates
  already present at compatible versions are reused; rewrite each new block's versioned dep refs, e.g.
  `thiserror 2.0.19`→the repo's `2.0.18`, matching by major) → add the new edges to the consuming crate's
  lock block + bump its version → `cargo build --offline` finalizes the lock WITHOUT touching the pinned
  drifted commits → verify `cargo build --locked` passes + `dig-constants`/`dig-nat` stayed at their
  locked revs. (Used to add `dig-ipc-protocol` + `dig-identity` in #1080.)

- **DISCOVER ≠ FETCH: a discovered holder must be REACHABLE, not just located (#1590, the final #836
  read-leg blocker).** On a relayed / isolated network the read path could DISCOVER a capsule holder
  (`find_providers`/`dig.getAvailability` returned it via the shared DHT) yet still 404, because the
  multi-source FETCH dead-ends: dig-download's locate offered only the holder's DHT provider record,
  whose advertised addresses (a direct `10.x`) the reader cannot dial on a relayed net. With no
  REACHABLE source the download failed, Tier-2 `peer_serve_plaintext` returned `None`, and the read fell
  through to the §21 whole-store backfill against `self.upstream` (hardwired to rpc.dig.net in
  `cache_fetch_and_cache`) → 400 → 404. The holder served ZERO `fetchRange` because no dial ever reached
  it (run e2e-1062-20260725-043357). The engine's `find_providers` (availability/redirect hint) and the
  Downloader's locate SHARE the same `CapsuleFallbackLocator`, so "discovered but not fetched" was NOT a
  divergent-locator bug — it was a REACHABILITY bug: the DHT record's addresses were undialable while the
  reader was ALREADY CONNECTED to the same holder in the gossip pool. Fix: `PoolProviderLocator` unions
  the currently-connected pool peers into the DOWNLOAD locator ONLY (never the redirect/availability
  hint — a redirect must name announced holders), so a fetch also tries peers reachable over the
  connection already held. dig-download's `getAvailability` confirm filters connected non-holders and the
  whole-resource merkle check binds bytes to the chain-anchored root, so offering the (pool-bounded) set
  is a safe probe. Lesson: on any relayed/NAT'd topology, "which peers hold X" (discovery) and "which
  peers can I actually pull X from right now" (reachable fetch sources) are DIFFERENT questions — a
  connected pool peer is the most reachable source there is, and must be a first-class fetch candidate.

## #836 read-leg DATA miss — the `getAvailability` confirm gate drops a connected holder

The prior #97 fix (pool address FIRST → `best_address()` reachable) fixed the DIAL address but not the
NEXT layer of the same 404. dig-download's `Job::locate_and_confirm` (orchestrator.rs) keeps ONLY
providers whose `dig.getAvailability` answer is `available` — it DROPS every other provider BEFORE any
`dig.fetchRange`. On a relayed/isolated net a holder the reader is already CONNECTED to (offered by
`PoolProviderLocator`) can answer availability=NOT-available as a false negative (its capsule may not be
in the `cache_list_cached` inventory `availability_presence` walks, a resource-vs-capsule granularity
quirk, or a transient probe failure). The confirm then drops it → `providers.is_empty()` →
`DownloadError::NotFound` ("no providers located for ContentId::Resource {…}") → ZERO `dig.fetchRange`
issued → the read falls through to the §21 upstream backfill → 404. This is the EXACT e2e symptom
("reader dials the holder :9444 [the availability probe] but never issues a fetchRange").

Ground truth on the two logged keys (ends the "key mismatch" misdiagnosis): `fetch_resource` logs
`content=%download_key(content)` and `download_key = ContentId::to_key().to_hex()`. For a
`ContentId::Resource{rk}`, `to_key()` hashes store+root+rk, so the logged `ea12da62…` IS the RESOURCE
key (NOT the capsule key — `capsule.to_key() != resource.to_key()`, dig-dht content.rs), and the
`befbbaf9…` in the `ContentId::Resource` Debug is that resource's raw `retrieval_key`. Same resource,
no key mismatch. The locate CHAIN (CapsuleFallback bridge + pool union + self-exclusion) resolves the
holder correctly in-process (PR#98's unit tests are green) — the drop is downstream, in the CONFIRM.

Fix (reader-side, dig-node): `PoolConfirmTransport` (download.rs) wraps the real range transport and
short-circuits `query_availability` to `available=true` for any provider whose `peer_id` is in the
connected pool — a live, connection-verified holder is confirmed by the connection itself; the
whole-resource merkle verify (NOT the self-reported availability flag) is the real integrity gate. A
DHT-only provider still goes through the real confirm. A connected non-holder simply fails its ranges and
is dropped there (bounded, safe).

Test gotcha — model a holder that answers availability=FALSE but WOULD serve: every prior read-leg mock
(`MockRangeTransport`, `AddressAwareTransport`) answers availability=true, so none could reproduce the
confirm-gate drop. The faithful model (`AvailabilityFalseButServesTransport`) answers availability=false
yet serves `fetch_range` — RED (no fetchRange, "no providers located") pre-fix, GREEN post-fix.

## An answer derived from an inventory SNAPSHOT while the serve path reads the FILE (#1592)

A whole class of "the node says no but would have said yes" bugs comes from two code paths answering
the same question from two different sources of truth. `dig.getAvailability` answered from the
`cache_list_cached()` DIRECTORY WALK of `<cache>/modules/<store>/`, while the serve path
(`serve_local_blocking` → `fetchRange`) reads `<cache>/modules/<store>/<root>.module` DIRECTLY. The
walk is a SNAPSHOT: `availability_batch` takes it once, then answers each item against that slice —
and every answer can await a `spawn_blocking` module decode, so the window between "snapshot taken"
and "answer produced" is real, not theoretical. Anything that lands a capsule inside that window (a
hosted pin, a §21 sync, an on-demand fetch-and-cache, a chain-watch gap-fill, the read-side backfill)
is SERVABLE but absent from the snapshot → the node answers *not available* for content it would serve
one millisecond later. The reverse also holds: a snapshot that predates an EVICTION claims
availability the node can no longer serve.

Why that specific false negative is read-killing rather than cosmetic: dig-download's
`locate_and_confirm` drops every provider whose availability answer is not *available* BEFORE issuing
any `fetchRange`. So a single stale *no* removes a genuine holder from the download entirely and the
read 404s. PR#100 worked around it reader-side for CONNECTED-pool holders only (connection =
confirmation); a DHT-discovered stranger still runs the real confirm, which is why the
discover-from-a-stranger leg stayed broken after the connected-pool leg was proven.

The durable lesson: when a peer-facing ANSWER and the ACTION it gates read different sources, the
answer will eventually lie. Derive the answer from the source the action uses — here a single
`module_exists()` path check, the same file the serve reads — so the two cannot drift by construction.
"Refresh the snapshot more often" only shrinks the window; it never closes it. Two bonuses fall out of
answering from the servable source: the cost drops from a whole-cache directory walk per peer request
to one `stat` per queried item (this is a peer-reachable path, so a per-request walk is a cost
amplifier a peer controls), and the walk is now needed only for the STORE-granularity `roots`
enumeration. The trade to watch: the keys are PEER-supplied and now feed a path, so they MUST be
validated canonical 64-hex before the join (the same guard `cache.removeCached` applies).

## A serve that logs nothing is indistinguishable from a request that never arrived (#1595)

Through the whole #836 read-leg bring-up the holder emitted **zero** log lines for an inbound
`dig.fetchRange`, at any filter level. So the single most valuable question in a read diagnosis — *did
the holder receive the request, and what did it answer?* — could only be answered by running `tcpdump`
on the instance, and "holder inbound = ZERO" stayed ambiguous for many rounds: silence looked exactly
like "never asked". Meanwhile the CLIENT side had already been instrumented (dig-download 0.7.2/0.7.3's
named-failing-step + per-candidate lines), which is precisely what turned six blind iterations into
one-run diagnoses on that side. The asymmetry was the whole problem: one end of the wire narrated
itself and the other was mute, so every failure landed in the mute half by elimination.

The durable rule: a peer-facing serve MUST announce its OUTCOME, not just its errors. Logging only the
failures is the trap — a *successful* serve that says nothing still leaves you unable to distinguish
"served fine, the reader broke" from "never reached us". The outcome vocabulary has to be a CLOSED set
(`served` / `not-held` / `bad-range` / `redirect`, and for availability `held` / `not-held` /
`rejected-non-canonical-key` / `store-roots`) with stable field names, so a diagnosis is a `grep` and
not a prose search. Two boundaries make it safe to keep on at INFO: it carries ids, counts and outcomes
ONLY — never payload bytes (which would make every operator log a copy of the served content) and never
proofs — and the ids logged are all values the peer itself supplied on the wire, so nothing is
disclosed that was not already public to that peer. Both boundaries are worth a real test; a log
assertion over captured records is cheap and it is the only thing that stops a future edit from
quietly reintroducing silence.

## The generation root commits RESOURCES, not chunks — so a per-range merkle proof does not exist (#1577)

"Per-range integrity" reads as though each served range should carry its own merkle inclusion proof
folded to the chain-anchored generation root. It cannot, and the reason is structural rather than a
missing feature: `digstore_core::merkle::resource_leaf(ciphertext)` is `SHA-256` of a resource's WHOLE
ciphertext, and every real tree in the store is `MerkleTree::from_leaves(resource_leaves)`. A chunk has
no committed digest of its own, and recomputing its resource's leaf requires every other chunk's bytes.
`MerkleTree::build` — the chunk-leaf constructor that makes the idea look feasible — has **no callers**
anywhere in the store; it is dead code, not the committed tree. Before building on a proof shape,
follow it to the code that actually COMMITS it; a constructor existing is not evidence a tree is built
that way.

Emitting a `range_proof` anyway would have been worse than emitting nothing: an unverifiable proof
invites a client to trust bytes it cannot check, which is the exact inversion of fail-closed. What was
genuinely missing, and is worth remembering as the general shape, is cheaper and real: the verification
metadata (`root`, `chunk_lens`, `total_length`, the whole-resource proof) used to ride the FIRST frame
only, while a downloader fetches ranges in PARALLEL from many holders. A peer serving only `offset > 0`
frames therefore declared no root at all, so the client's consistency check had nothing to compare and
a wrong-generation source was undetectable until the whole resource had been paid for in bandwidth.
Making every frame self-describing closes that at the cost of a few dozen bytes per frame.

The constraint that bounds the fix: the served window must stay EXACTLY the requested span. Expanding
it to chunk boundaries (tempting, since a chunk-aligned span is the verifiable unit) breaks every
verifying client, because `verify_range` fails closed on any length but the one the client planned.
When a server and a client both compute a span, the client's plan is the contract.

## Reshare: the announce is driven by a FILE PATH, not by a function call (#1576)

The node's DHT provider records are derived from its cache inventory, so **the existence of
`<cache>/modules/<store>/<root>.module` IS this node's network-wide claim to be an authoritative holder
of that capsule.** There is no "announce()" you can forget to guard — writing the file is the announce.

Consequence for any code that produces a module (a gap-fill, a §21 sync, a reshare pull): it MUST NOT
stage anywhere under the cache. A whole-capsule pull that staged at the cache path would advertise a
half-downloaded capsule for the duration of the download, and a *failed* pull would leave a permanent
claim to content the node cannot serve. The reshare leg therefore stages under `<downloads>` and moves
into the cache (write-then-rename) only after the pull succeeded AND the artifact was re-proven.

## A hash gate cannot detect the empty module (#1576)

`ModuleDownloader` runs two hash gates before admitting a module: every chunk against `chunk_hashes`,
then the whole blob against `module_hash`. **Both pass trivially for a 0-byte module.** The attacker
declares `total_size: 0` and `module_hash: sha256("")`, serves nothing, and `sha256(&[])` genuinely
equals the declared value — the arithmetic is correct and the module is worthless.

More generally: every check before the chain-anchor gate compares attacker-chosen bytes against
attacker-chosen hashes. They prove SELF-CONSISTENCY, never authenticity. The anchor gate — the module's
committed `CurrentRoot` versus a root resolved from the CHAIN — is the only check that says anything
about authenticity, which is why the empty-blob and unparseable-blob rejections live in the verifier and
not somewhere more convenient.

## "verified artifact" and "promoted artifact" are different objects (#1576)

`ModuleDownloader` verifies an in-memory blob, then promotes a STAGING FILE. Those are two objects, and
`download() == Ok` only speaks about the first. Anything that can touch the staging file between the gate
and the promotion (another process, a leftover tail from a longer earlier attempt, a crash mid-rename)
breaks the equivalence silently — the caller sees success and caches something that was never verified.

The external check is to re-hash the file about to be promoted. The reference for that comparison must
NOT be the descriptor's `module_hash`: that value was chosen by the serving peer. Instead the anchor
verifier records the digest of the bytes it actually ADMITTED — it is the only component that ever sees
the fully-assembled, gate-passed blob — and the promotion compares against that. Both sides of the
comparison are then the node's own.

## A caret dep can be right while the resolved tree is wrong (#1576, sibling of #836)

dig-download 0.8.0 depended on dig-rpc-protocol `"0.5"` — correct — and still resolved **0.3.1 as well**,
because dig-peer 0.4.1 pulled the older major. Two `ModuleInfo` types then sat either side of the module
pull's trust boundary, on `chunk_hashes`/`chunk_lens`: the fields that drive the whole pull plan. Rust
compiles that happily; it presents as content that arrives and never verifies (exactly #836's
`serde_bytes`-vs-base64 range-frame skew, six blind diagnosis rounds).

Two lessons, both now enforced by tests that read `Cargo.lock`:

1. Assert the invariant against the **resolved lock**, not the manifest. `cargo tree -i <crate>@<version>`
   names the culprit in one command.
2. The culprit is often **your own workspace**. After bumping dig-node-core to dig-rpc-protocol 0.5, the
   lock STILL carried 0.3.1 — from `dig-node-service`, the shell in the same repo, whose own pin nobody
   had thought to bump. A cross-repo cascade is not finished until every crate in the consuming workspace
   is on the new major.

## Cargo features can smuggle a fail-open bypass past every test (#1576)

dig-download compiles its fail-OPEN `AcceptAnyModuleAnchor` out of a default build (`cfg(any(test,
feature = "testkit"))`) precisely so a production wiring cannot name it. That protection is a **manifest
edit** away from gone — and the edit compiles, and every existing test still passes.

So the protection needs a test that reads the manifest: `testkit` must appear only under
`[dev-dependencies]`, never on the production edge (dev-dependency features do not propagate to
consumers, so the binaries never see it). A guarantee enforced by build configuration needs an assertion
at the build-configuration level; a unit test cannot reach it.

## `complete: false` means "the RESOURCE continues", not "the STREAM isn't done" (#1619)

`dig.fetchRange`'s per-frame `complete` flag reports whether the assembled window has reached the
RESOURCE's end. It says nothing about whether the caller's REQUESTED SPAN (`offset..offset+length`) has
been satisfied — those are two different bounds, and `stream_range`/`stream_fetched_range` conflated
them: the streaming loop kept re-requesting more frames until `complete` (or an empty frame), ignoring
`length` entirely past the first call. dig-download sends `{offset:0, length:1}` as a routine
metadata-probe on EVERY download (`establish_commitment`), so this silently turned a ~100-byte probe
into the ENTIRE resource streamed over the wire — real production traffic amplification, not a
theoretical edge case, and it shipped for as long as no test's fixture happened to exceed one node
window (dig-node's own #836/#1592 e2e proofs passed only because those fixtures were 20477 and 27067
bytes, both under the per-frame cap — the corrected record is in dig_ecosystem#836).

**The fix is a SEPARATE bound, not a replacement one:** stop the loop when EITHER `complete` (resource
exhausted) OR the requested span is satisfied (`off + this_len >= offset + length`) — and request only
the REMAINING span each iteration, never the original `length` again. A reimplementer who reads
`complete` as "the stream may stop now" will get exactly this bug; the two concepts need distinct names
in any port of this logic.

**Test-design corollary:** a "streams N frames" test whose frame count comes from a small `length` on a
small fixture cannot tell this bug apart from correct bounded behaviour once `length` genuinely spans
multiple node windows — the fixture has to actually EXCEED one window ([`crate::peer::RANGE_WINDOW`], 3
MiB) for a multi-frame assertion to mean anything.

## N refusal tests + zero success tests cannot tell "correctly refuses" from "can only refuse" (#1576)

`CapsuleWarmer::warm()` shipped with four tests, all four asserting a REFUSAL (`PullFailed`,
`NoChainAnchor` ×2, a bad id) — `WarmOutcome::Held` appeared only at its construction site, never in an
assertion. A wiring slip that made `warm()` ALWAYS refuse (e.g. a broken staged→cache path, a dropped
`Ok` arm) would have shipped green: every existing test passes whether the code can succeed or not.

The general shape: a function with several distinct outcomes needs at least ONE test per REACHABLE
outcome, not just per REFUSAL reason — proving the happy path exists is a different assertion than
proving every failure mode is handled, and a suite that only does the latter looks complete while
leaving the former provably untested. When adding a test for a success path that was missing, confirm it
is non-vacuous by breaking the success arm (return the refusal unconditionally, or point the promotion at
the wrong path) and watching the new test — and ONLY the new test — go red.

## `dig-download`'s `FileStateStore` key exceeds Windows' filename length limit (#1639)

`FileStateStore::path_for` hex-encodes its key (doubling its length, to keep it filesystem-safe) before
writing `<dir>/<hex>.json`. That is safe in isolation, but `module_download_key` builds the key as
`"module:<64hex-store>:<64hex-root>"` (136 chars) — hex-encoded, 272 chars, plus `.json` — comfortably
over the ~255 UTF-16-code-unit limit NTFS enforces on a path COMPONENT without long-path opt-in
(`\\?\` prefixing). The result is a real `ERROR_INVALID_NAME` (os error 123) the moment a warm actually
reaches `state_store.save()` — which the #1576 reshare leg's own refusal-only test suite never did,
since every refusal short-circuited before a checkpoint was ever written (see the entry above: N
refusals prove nothing about the path only the success case exercises). `CapsuleWarmer` wires a REAL
`FileStateStore` in production (`download.rs`'s `wire_capsule_reshare`), so a Windows-hosted dig-node
running the reshare leg hits this for real, not just in a test harness.

Composing a filesystem key from two 64-hex ids plus a literal prefix, then doubling it via hex-encoding,
is the kind of length math that is easy to miss until a REAL save actually runs — worth checking against
the OS limit (255 for a bare NTFS component, ~32,767 with `\\?\` long-path opt-in) whenever a cache/state
key is built by concatenating content ids rather than hashing them down to a fixed width.

## A comment asserting an invariant is how a security defect survives an audit (#1576)

The reshare leg's origin gate was fixed on the JSON-RPC plane, and then the SAME false premise turned up
one file over, written as a comment above `peer_serve_plaintext`'s `fetch_resource` call: "this whole tier
only runs behind the LOCAL loopback plaintext read … never the peer wire". It read like a checked fact, so
a reviewer walking the call graph stopped there instead of walking to the two production callers — which
are on the single flat `Router` served on EVERY listener, with `Config::bind_addr()` = `host.unwrap_or
(127.0.0.1)` and no loopback validation on the `DIG_NODE_HOST` override. `GET /s/<store>:<root>/index.html`
with `Host: localhost` therefore reached the reshare leg unauthenticated. The PR made it worse than the
pre-existing state: before, that door reached only the §21-AUTHENTICATED upstream sync, which can fail for
want of authorization; after, it reached a peer-to-peer pull that needs none.

Two durable lessons:

1. **A security label must be a PARAMETER, never a comment.** If a function's correctness depends on who
   is calling it, the caller must pass that fact in. A comment claiming "the caller is always local"
   cannot be enforced by the compiler, does not survive a new caller, and — worse — actively suppresses
   the check a reviewer would otherwise perform. Replace such a comment with the derivation itself
   (`SPEC.md` §21.7 now states the rule normatively).
2. **Fixing an instance is not fixing the premise.** When a false assumption is found at one call site,
   grep for the ASSUMPTION (here: any place asserting a read is local because of the endpoint it arrived
   on), not just the symbol that was patched. The second instance was three call sites plus a fourth in
   the same file.

Testing note: the label's derivation could not be exercised by a server bound to loopback, which can never
produce a non-loopback remote address. The test drives the REAL router through `tower::ServiceExt::oneshot`
with a FORGED `axum::extract::ConnectInfo` — the same extension `into_make_service_with_connect_info`
inserts in production — so the two arms differ ONLY in the connection's address. That matters for more than
convenience: asserting the OUTCOME ("no warm started") alone would have been satisfied by a guard at the
wrong layer, since a filter anywhere below produces the same empty result. Recording the label at the seam
boundary makes a RELOCATED guard observable.

## A security property asserted from an unenforced config assumption is a false premise — enforce it or cite the real control (#1662/#1663/#1664)

For ~25 comments the service asserted the local API was "loopback-only / never peer-reachable", but
`parse_host_override` accepted ANY IP literal with no loopback check — so `DIG_NODE_HOST=0.0.0.0`
silently made the RPC/content API peer-reachable while every one of those comments claimed it could
not be. An assertion that a bind "is loopback-only" is worthless when nothing enforces it. Two ways
to make such a claim TRUE, both applied here:

- **ENFORCE the assumption.** `host_override_refusal` (config.rs) refuses a non-loopback
  `DIG_NODE_HOST` at startup unless `DIG_NODE_ALLOW_REMOTE=1` (opt-in, same money-safe shape as the
  live-broadcast flag). Fail-closed at the bind site (`serve_with_shutdown`), NOT in `from_env`, so
  the non-binding CLI commands (`status`/`install`) still resolve whatever the operator set. Now the
  loopback comments are enforced invariants, not hopes.
- **Cite the REAL control, not the bind.** The control surface was documented "loopback-admin-only
  (never peer-reachable, #179)" — but its actual protection is the paired-token gate enforced
  fail-closed in `server::rpc` (#1663). An operator MAY deliberately opt into a remote bind, so the
  control plane must never lean on the bind for authorization; the token gate holds regardless of
  where the call arrives from. The bind is defense-in-depth beneath it.

Sharp edge — **IPv4-mapped loopback (#1664b).** On a `::` dual-stack bind the OS reports an IPv4
loopback client as `::ffff:127.0.0.1`, and `Ipv6Addr::is_loopback` is `== ::1` ONLY, so the origin
classifier mislabelled the operator's OWN reads as `Peer` and silently disabled the local warm-up
flywheel. The shared `is_loopback_addr` helper unwraps the mapping with `to_ipv4_mapped()` — one
loopback predicate reused by both the origin label and the `DIG_NODE_HOST` enforcement (and #1646).

Coherence: `DIG_NODE_HOST` governs ONLY the local RPC/content bind; the peer P2P wire (mTLS, in
dig-node-core) and the loopback wallet mTLS `:9776` listener bind independently, so enforcing
loopback here never breaks peer connectivity. A remote-API test rig (#1062) just sets the flag.

## Lane anchor — dig_ecosystem#1667 (loopback-enforcement residuals)

A fail-closed guard is only good UX if it fires at the EARLIEST point the bad config is known. #1662 enforced the non-loopback `DIG_NODE_HOST` refusal at the bind site, but `dig-node install` baked the host into the service env WITHOUT re-checking — so an unauthorized `DIG_NODE_HOST=0.0.0.0` installed cleanly and only failed closed on first service start (confusing: the failure is detached from the action that caused it). Fix (#1667): `install()` now calls the SAME `config::host_override_refusal` before any side effect, so the refusal surfaces the identical message up front. Reuse the one canonical predicate — never re-derive the loopback rule. Also swept the residual bare "loopback-only" comments in meta.rs/lib.rs: the control surface is token-gated REGARDLESS of bind (loopback-bound only by default; non-loopback with `DIG_NODE_ALLOW_REMOTE=1`), and control.* is never peer-reachable regardless of bind — the imprecise adjective, though safe today, understated the real invariant.

## Lane anchor — dig_ecosystem#1668 / #1640 (the range-frame ceiling)

**STATUS: RESOLVED at dig-nat, and the node is now ON the fixed line.** dig-nat 0.13 shipped the
capped/paged SENDER (fallible `RangeFrame::encode` + the paged prologue) and 0.14 the receiver-side
`ChunkLensAssembler`; both fail CLOSED, so an over-ceiling frame is a clean boundary error rather than
a silent mid-read decode failure. The 0.14 line (dig-gossip 0.17, dig-dht 0.8, dig-download 0.12,
dig-peer 0.7, dig-peer-selector 0.7) landed as the single atomic cascade the note below anticipated,
so the "this node cannot reach 0.14 yet" paragraph is HISTORY, kept for the lesson it carries about
duplicate wire crates. `RANGE_WINDOW` remains the node's per-frame SPLIT size and is no longer a
KNOWN CONSTRAINT.

**One confused quantity made every DIG read above ~48 KiB impossible, network-wide.** `RANGE_WINDOW`
(3 MiB) bounds how much ONE REQUEST may ask for. `dig_nat::MAX_RANGE_FRAME_PAYLOAD` (32,768 B) bounds
ONE FRAME. The serve path framed on the former against the latter — 96x over — and because `bytes`
travels base64, any resource past roughly 48 KiB produced a body over `MAX_FRAMED_BODY` (65,536) that
every conforming receiver is REQUIRED to reject. Both names contain "range" and both are byte counts,
which is precisely why they were interchanged.

**The defect was structurally invited.** The serve path hand-built frames as `json!` and wrote them
with `peer::write_framed`, which has NO cap: it serialises and writes a raw `u32` length prefix. So the
SENDER could not learn it had produced something the receiver must reject — the asymmetry could only
surface as a failed read in production. Frames are now built as real `dig_nat::RangeFrame` values and
written through `RangeFrame::encode`, which refuses an over-ceiling payload/proof/body. **The durable
lesson: when one side of a wire rule can be maintained separately from the other, it eventually will
be. Route both sides through the same type.** (dig-nat's own `MAX_FRAMED_BODY` doc names dig-node's
`write_framed` explicitly as an implementation that must use the value.)

**A test suite can be complete and still blind.** Every pre-existing range-serve test either inspected
the `serde_json::Value` the serve path built or streamed into `tokio::io::sink()` — neither touches the
encoder, so all of them passed against a 96x-oversized frame. Worse,
`stream_range_paces_each_frame_under_a_tight_cap` asserted `frames: 2` for a 3 MiB resource: it PINNED
the bug as correct behaviour. The read-leg e2e proofs that "passed" served 20,477 B and 27,067 B —
both under the ceiling. **Size a fixture FROM the protocol's own published limits and say why; a
fixture that cannot exceed a bound cannot detect an unbounded encoder.**

**Narrowness, not error — proved on this lane's own tests.** The paged-prologue test (six data frames
carrying three pages) genuinely CANNOT detect setting `complete` as soon as the bytes are done: the
prologue finishes long before the last frame, so withholding it changes nothing observable. Only a
span SMALLER than the prologue separates the behaviours (one data frame, three pages). Reverting that
one line left the paged test green and failed only the dedicated fixture. **When a fix is about
ORDERING or PLACEMENT, ask what input makes relocation observable — the obvious "bigger" fixture is
often the blinder one.**

**dig-nat 0.13 vs 0.14 — a version is not automatically the right target.** 0.13 introduced the whole
capped/paged SENDER API (fallible `encode`, `with_identity`/`chunk_count`, `with_chunk_lens_page`,
`skip_layout`); everything 0.14 adds is the RECEIVER (`ChunkLensAssembler`) plus `split_chunk_lens_pages`.
This node cannot reach 0.14 yet: it passes its OWN `dig_nat` `NodeCert`/`NatConfig`/`NatRuntime` values
INTO dig-download (`NatRangeTransport::new_with_runtime`) and dig-gossip, and those sit on `^0.13`, so
requesting 0.14 resolves THREE dig-nat instances and the calls stop typechecking. **A duplicate wire
crate is a compile break here, not a size regression** — `tests/dependency_tree.rs` asserts the
TRANSITIVE LOCK entry for exactly this reason, and a caret dep looking correct proves nothing.

**`chunk_lens` is a DECRYPT input, not a verify input.** Per-chunk AES-256-GCM-SIV needs the whole
array summing to `total_length`, so a partial layout is unusable rather than partially useful. That is
why a paged prologue must complete before a stream ends — including on a one-byte request, where the
remaining pages ride zero-payload frames — and why `complete` is withheld until the last page is out.

## An address is a TYPE, not a string — and a fixed guard's allowlist takes its detectors with it (#1682, #1722)

`Config::bind_addr` rendered `DIG_NODE_HOST` and the port with `format!("{host}:{port}")`. For an
IPv6 host that yields `::1:9778`, which is not a socket address in the grammar — and since a bind
failure on that listener is documented FATAL, configuring the address family §5.2 PREFERS took the
node down. The lesson is not "remember to bracket": it is that a function returning `String` cannot
stop the next caller, so the accessors now return `SocketAddr` and the authority can only be rendered
by `SocketAddr`'s own `Display`. Typing it found two further live defects nobody had ticketed — the
control client's `http://{addr}/` JSON-RPC URL and the `extension_host` operator log line — because
both consumed the same broken string.

Two things worth carrying beyond this fix:

**A guard's allowlist can be load-bearing for the guard itself.** The #1593 source scanner proved it
had escaped its own crate by asserting `waived == KNOWN_VIOLATIONS.len()`: both tracked violations
lived in the sibling crate `dig-node-service`, so reaching them proved the scan's reach. Fixing both
defects emptied the list and turned that assertion into `0 == 0` — the check evaporated at exactly
the moment it succeeded, and nothing would have reported it. When you pay off a tracked-violation
list, look for what the list was incidentally proving; here the reach detector was replaced with a
direct assertion that the scan read files from the sibling crate. Same property, no dependence on
debt existing.

**A ticket saying "the margin is zero" may be measuring a different relation than the one it names.**
#1722 reported dig-node's `ADVERTISED_TTL_SECS` as having zero margin against dig-dht's
`provider_ttl`. It has an hour of margin against `provider_ttl` (1h vs 2h) and zero against
`republish_interval` (1h vs 1h) — two distinct relations with opposite failure modes: exceeding
`provider_ttl` gets the claim silently clamped, while a `republish_interval` above the advertised TTL
makes records expire before the holder re-announces. Pinning only the named relation would have left
the real one unguarded. No single value satisfies both bounds with margin, so closing the zero margin
is a wire-behaviour decision, not a test fix.

**Landing a capsule IS announcing it — verify at the land seam, not only at serve (#1623).** The
whole-store sync (`sync_module_from` → `cache_fetch_and_cache`) writes a downloaded module straight to
`<cache>/modules/<store>/<root>.module`, and the mere existence of that file makes the node a
discoverable DHT holder (§14.1) — the reshare/flywheel then multiplies the copy across peers. So the
old rationale "the synced module isn't trusted here; a tampered module fails the SERVE gate, not this
sync" was wrong: the serve gate never runs for a peer that only learns this node HOLDS the capsule
from its DHT announce. The fix reuses the #1576 reshare leg's `ChainAnchoredModuleVerifier` at the sync
seam (resolve the chain-anchored root, re-hash, compare) and refuses BEFORE the write, so an
unverified capsule never lands and is never announced. General lesson: a defense that only runs on one
of several exit paths is not a defense — verify at every seam that admits an artifact.

**Loopback != operator-authorized; provenance is a SECOND axis over ReadOrigin (#1654).** The read-origin
gate (#1576) labels a `/s/` read `Local` when the connection is loopback — but a loopback address only
proves the CONNECTION is local, not that the OPERATOR authorized the request. A browser running an
attacker's page can issue a cross-site `GET dig.local/s/<capsule>`: loopback ⇒ `Local` ⇒ the attacker's
chosen capsule LANDS (warm + reshare + DHT holder-announce), a remotely-triggerable amplification of the
attacker's choosing at the cost of a few bytes. The bytes themselves are harmless (public content); the
durable holder side effect is the vulnerability. Fix: a second orthogonal axis, `RequestProvenance`,
derived from the browser's own `Sec-Fetch-Site` header — only an explicit `cross-site` is `CrossSite`;
absence is `FirstParty` (CLI/SDK send no `Sec-Fetch-*`, and treating absence as cross-site would silently
stop every CLI/SDK read from landing). Landing fires only when BOTH `Local` AND `FirstParty`; a cross-site
read collapses its landing origin to `Peer` (`landing_origin(origin, provenance)`), serving the bytes
identically but effecting nothing. Also token-gated `cache.fetchAndCache` over HTTP (it is an explicit
"become a holder" call, not a public read); the in-process FFI `cache.*` path stays open. General lesson:
a transport-derived trust label (loopback) can be a NECESSARY but not SUFFICIENT condition — a CSRF-class
attacker rides the trusted transport, so a durable side effect needs a second axis the attacker cannot
forge (here, the browser's own cross-site self-report).

## The miss→DHT-lookup path is a per-requestor amplification surface; key the bound by identity, not origin (#2007)

A content miss (`Node::miss_outcome`) runs a DHT `find_providers` lookup — and, on an explicit
`proxy`, a whole multi-source fetch — ON BEHALF OF THE CALLER. Both spend THIS node's network
bandwidth, so a caller that names arbitrary `(store,root,rk)` triples it does not actually want is an
amplification/oracle vector even though it holds and pulls nothing itself. The bound that matters is
PER REQUESTOR: a single global bucket would let one abuser refuse every other caller's misses (a
denial surface), so the limiter (`crate::rate_limit::MissRateLimiter`) keys by the mTLS-verified
`peer_id` for a peer, the connection IP for an anonymous/gateway HTTP caller, and one shared bucket
for the trusted operator loopback. The subtle wiring cost: the peer JSON `dig.getContent` miss loses
the caller `peer_id` before it reaches the shared `dispatch`, so the identity must be threaded
EXPLICITLY (`handle_json_rpc(req, conn_key)` → `handle_rpc_as(..., RequestorId::Peer(conn_key))`) —
inferring it from `ReadOrigin` alone collapses all peers onto ONE bucket. The tracked-requestor table
is bounded and evicts ONLY full (idle) buckets, because dropping a full bucket recreates it
identically and so can never weaken a live limit — evicting a partially-drained bucket WOULD.

Two design boundaries worth keeping: (1) a redirect NAMES holders but this node never dials/probes
them — probing-on-miss is itself the amplification vector, and reachability is the requestor's job via
its own ladder (NAT asymmetry: "peers I can reach" ≠ "peers the requestor can reach"), so the
candidate set is merely capped (`MAX_REDIRECT_PROVIDERS` = dig-dht `MAX_ADDRESSES_PER_RECORD`). (2)
the explicit `proxy:true` fallback reuses the EXISTING `FetchThrough` branch + the identical
chain-anchored merkle-verified `fetch_resource`, and keeps the `origin != Local` reshare refusal
intact — the proxy serves bytes but the middle node does NOT become a holder, so it cannot be used to
plant attacker-chosen inventory. `TokenBucket` here is a byte-identical MIRROR of dig-wallet's #1957
primitive (dig-node-core must not depend on dig-wallet); consolidating both into a lower shared crate
is the remaining follow-up.

## A retention ceiling is NOT a response ceiling — an anonymous whole-section render needs its own bound (#2145)

The decoded-manifest memo already bounds RESIDENCY: total bytes (`MANIFEST_MEMO_MAX_BYTES`, 32 MiB,
LRU-evicted) with a per-entry ceiling (`MANIFEST_ENTRY_MAX_BYTES`, 4 MiB) so one hostile capsule can
neither pin the budget nor evict everything to fit. But that ceiling governs what is KEPT, not what is
SENT. `dig.getMetadata` renders a WHOLE data section into one JSON-RPC response — it cannot be windowed
like `dig.getContent`/`dig.getCapsule`, whose 3 MiB windows seek the module — and `MetadataManifest`'s
`custom`/`links` are publisher-controlled and unbounded. So a section that is REFUSED memoization (over
4 MiB) is re-decoded per request AND still rendered + parsed + re-serialized (3–4 in-RAM copies) into
the response on every anonymous call: a ~200-byte request → ~100 MB out. The fix is a separate RESPONSE
ceiling (`METADATA_RESPONSE_MAX_BYTES` = `WINDOW` = 3 MiB): check the RENDERED length BEFORE parsing and
refuse with a bounded `METADATA_TOO_LARGE` (-32015). Note the two ceilings deliberately differ (4 MiB
retain vs 3 MiB respond), so a 3–4 MiB section is memoizable yet un-servable — that is correct, both are
DoS bounds, not a wire contract. Second gap in the same class: a lifetime-of-process memo with no idle
TTL is only reclaimable if `cache.clear` actually DRAINS it — `clear_cache`/`clear_content_cache` did
not touch the manifest memo, so an operator clearing the cache still held its RAM until process exit.

## Size the INPUT and MEASURE the peak — do not size the decoded output (#2160)

The `dig.getMetadata` cold decode holds ~1.1 GiB transient at peak, and a hostile `custom` decoded from
JSON TEXT expands ~16× (a flat-numeric `[0,0,…]` becomes one `serde_json::Value` node per element, ~2
bytes of text → ~24+ bytes of node), so a `custom` filling a 128 MiB section reaches ~2 GiB on a ~1.9
GiB host. Hand-sizing that decoded `MetadataManifest` failed five rounds in PR #179 — a recursive,
attacker-shaped value has unboundedly many places to be wrong and the compiler checks none of them.

The durable lesson, two halves: (1) cap the INPUT structurally BEFORE decode — the ENCODED section
length (3 MiB, equal to the response ceiling, so it refuses nothing that was servable) plus the `custom`
shape (entry count + JSON depth + node count, streamed over the raw text, never materialized). Refusing
the oversized/hostile section before `MetadataManifest::decode` removes the expansion a rendered-output
check can only see after it has already happened. (2) PROVE it with a counting allocator, not by
reasoning: a `#[global_allocator]` test harness with THREAD-LOCAL current/peak counters (so parallel
`cargo test` threads don't pollute the reading, and production is untouched under `#[cfg(test)]`) drives
one cold decode and asserts the measured peak stays under budget — run BOTH the capped and uncapped path
on the same bytes so the budget sits strictly between them and the test cannot go vacuous.

Sharp edge — advancing the wire cursor without re-implementing it: the shape scan must reach the
`custom` block past a dozen leading fields. It decodes those with the store library's OWN `Decode` impls
(discarding the values) so the wire format lives in one place and cannot drift; only the `custom` block
is read by hand, and each value's JSON text is read as RAW BYTES — never `serde_json`-parsed — so nothing
the hostile value describes is ever materialized.

## dig-constants drift is a chia-line boundary, not a version-string gap (#2072)

dig-node's lock carried FOUR `dig-constants` copies at once (0.1.0, 0.4.0, 0.5.1, 0.8.0) against a
published tip of 0.10.0. The instinct is to read that as four stale pins. It is not: only two of the
holders are dig-node's own crates. The rest are held down by upstream crates whose PUBLISHED metadata
names an old range, and a published range cannot be edited from a consumer — `dig-gossip` (`>=0.2, <0.5`),
`dig-nat` (`>=0.4, <0.6`), `dig-download` (`^0.8`), `digstore-chain` (`^0.5`), `dig-clvm` (`^0.9`). Each
needs its own release before dig-node can unify. Derive that set from `cargo tree -i dig-constants@<ver>`;
a manifest read shows only the two pins dig-node owns and hides the other five entirely.

**The 0.10.0 tip is not reachable from this workspace at all, and the reason is not dig-constants.**
0.9.0 → 0.10.0 moved the crate from `chia-protocol` 0.26 / `chia-wallet-sdk` 0.30 to 0.36.1 / 0.34.
dig-node builds against the 0.26 line, including a VENDORED `chia-protocol` fork that `dig-gossip`
supplies through `[patch.crates-io]`. Depending on dig-constants 0.10 therefore links a SECOND
`chia_protocol` into the graph, and `DIG_MAINNET.genesis_challenge()` returns a `Bytes32` that no
function in the workspace accepts — eleven type errors of the form "expected `BytesImpl<32>`, found
`chia_protocol::bytes::BytesImpl<32>`". Being current on dig-constants is downstream of migrating the
whole node to chia 0.36; it is a platform migration wearing a dependency bump's clothes. 0.9 is the tip
of dig-node's chia line and is the correct target until that migration lands.

**The one value that actually moved: the DIG L2 genesis challenge, in 0.1.0 → 0.4.0.** 0.1.0 shipped an
all-zeros PLACEHOLDER `DIG_MAINNET_GENESIS_CHALLENGE`, with all six AGG_SIG additional-data domains
correctly derived from that placeholder — self-consistent, so no derivation test could see it. 0.4.0
finalized the real challenge (`0af98186…`) and recomputed all six. Every value is stable from 0.4.0
through 0.10.0; 0.5.1/0.8.0/0.9.0 are purely additive (DIG_ASSET_ID, treasury hash/address, DEK labels,
`dig.local`, `rpc.dig.net`), and 0.9.0 → 0.10.0 changes only upstream chia plot-consensus FIELD NAMES,
no DIG value. So a bump anywhere at or above 0.4.0 is value-neutral, and the ONE copy that mattered was
0.1.0 — reached through `dig-clvm` 0.1.1, pinned by git rev in dig-wallet, whose spend-validation
`ValidationContext` therefore described a different chain identity than the rest of the node. Nothing
was mis-signed (that call site sets `DONT_VALIDATE_SIGNATURE`, and the signing domain is injected by the
caller, not read from `DIG_MAINNET`), but the divergence was one refactor away from mattering. Moving
dig-clvm to crates.io `0.2` removes it.

The general lesson: when a shared-constants crate shows several versions in one lock, diff the VALUES
across them before treating the collapse as a chore, and diff the crate's own dependency line before
treating the tip as reachable. Here the version count was the least informative number in the problem.

The placeholder was invisible to the test suite in both directions, and the reason generalizes: no
source line pins the genesis literal (`grep 0af98186 --include=*.rs` finds nothing), and every runtime
check reads `dig_constants::DIG_MAINNET.genesis_challenge()` on BOTH sides of its comparison. That is
circular — it passes identically under the real value and under an all-zeros placeholder, so the suite
stayed green while the defect shipped AND stayed green after it was fixed. A constant that is only ever
compared against itself is unguarded no matter how many assertions mention it. The guard therefore lives
where the defect is decided, in `dig-node-core/tests/dependency_tree.rs` against the workspace lock, as
a FLOOR (no copy below 0.4.0) rather than an inequality against the one known-bad release — 0.2.x and
0.3.x carry the same placeholder, so `!= "0.1.0"` would be bypassed by the next one.

## Never bind another wallet's port, and never lose a port silently (dig-node#260)

The Sage-parity wallet mTLS listener defaulted to `9257`, which is Sage's OWN RPC port
(confirmed in Sage's source: `sage-config`'s `RpcConfig::default` sets `port: 9257`). The
parity we wanted was of the METHOD SURFACE; taking the port bought nothing and cost a user
their wallet: dig-node is an auto-starting OS service and Sage is a desktop app, so after a
reboot dig-node reached the socket first. A Sage client then opened `9257`, met our mutual-TLS
listener, presented no cert we accept, and OUR SERVER sent `handshake_failure` — which the
client surfaces as an OpenSSL error, three layers from the cause. The user spent an afternoon
looking at their system TLS configuration. It is now `9776`, beside the rest of the DIG
cluster, and the prohibition is a test rather than a comment.

The second half is the one worth generalising: the bind was best-effort AND silent. When two
processes contend for one port the loser is exactly the party who needs to be told, and a
`NON-FATAL` log-nothing branch guarantees neither side learns anything. Best-effort means
"does not stop the node", never "is not reported": the outcome is now logged at WARN and
published on `control.status`, so `dign info` says `wallet mTLS UNAVAILABLE (port 9776 held by
another process ...)`. Any other best-effort bind in this repo should be read the same way.

## A "quorum" is only as independent as what its members can REACH (dig-node#365)

Corroboration rules fail in one characteristic way here: the sources are counted, not weighed. On
PR#354 a 2-of-2 "independent-group" rule in `dig-wallet` was satisfied by ONE HTTPS endpoint,
because the second group's peer tier was configured with `max_peers: 0` and could reach nothing at
all. The rule was correct about its own definition of a group and wrong about the world.

So `seams/chia_peer/endpoints.rs` derives independence from RESOLVED ADDRESSES: two endpoints are
one voice when their address sets intersect, transitively. Not their type, and not their host name
— a CNAME costs an attacker nothing, and two names for one machine is exactly the shape a name-based
rule waves through.

Two consequences worth knowing before touching it:

* **Set INTERSECTION, not equality.** A dual-stack host answers with several addresses (§5.2 makes
  IPv6 the ordinary case), and a resolver returning different subsets on two lookups would make one
  machine read as two voices under an equality rule.
* **The merge must be transitive.** An endpoint bridging two previously-disjoint groups makes all
  three one voice; stopping at the first matching group leaves the second counted separately, and a
  third endpoint then turns one host into a passing quorum.

## Refusing on a default install is not a safe default (dig-node#365)

The anchored root decides which bytes a user is served, so a single-source resolution of it is a
real gap. Refusing to resolve it without corroboration would close the gap and stop every
unconfigured node serving any content at all — including the surfaces on which an operator would
then configure a second endpoint. The shipped rule therefore degrades to the single source, states
that in `SPEC.md` §14.4b as an accepted limitation with its blast radius, and refuses only where two
independent voices exist and DISAGREE. "State it honestly" is a legitimate outcome; implying
corroboration the code does not perform is not.

## Widening a source-scanning guard widens its blind spots (dig-node#366)

The NC-12 sole-owner sweep is a line classifier over Rust source, and it took five gate rounds to
make honest within one crate. Adding `dig-node-core` to its haystack surfaced two failure modes that
a wider scope creates rather than inherits:

* **File names repeat across a workspace.** Sites were reported as bare basenames and the owner was
  `"sources.rs"`, so a second fabric built in a `sources.rs` in ANY newly-swept crate would have
  been accepted as the owner. Sites are now crate-qualified (`dig-wallet/sources.rs:NNN`).
* **A crate with none of the needle cannot tell you it was read.** `dig-node-core` contains no
  `ChiaQuery::new(` at all, so a total taken across both roots stays positive from `dig-wallet`
  alone — a typo in the second path leaves the new scope reading zero files while the guard still
  reports a real haystack. The haystack test now asserts a FILE count per root, which separates
  "this crate is clean" from "this crate was never opened".

Both known-silent shapes were re-measured against the new haystack. The column-0 `#[cfg(test)]` as
string content is absent from both crates. The trailing-comment terminator occurs ONCE, at
`dig-node-core/src/lib.rs:195` (`const DEFAULT_CACHE_CAP: … ; // 1 GiB`) — harmless only because no
column-0 `#[cfg(test)]` precedes it in that file, so the latch is never set when it is reached. That
is a property of where the line sits, not of the line, and nothing would report it if it moved.

## A yes/no answer cannot carry a dissent, and a threshold hides that (dig-node#365)

`Result<(), String>` has no value channel, so a source saying *"that root is not current"* and one
saying *"I could not reach the chain"* arrive as the SAME `Err`. An agreement rule reading that
cannot tell dissent from silence, and the natural implementation — drop the errors, count the `Ok`s,
require two — is a flat *k*-of-*N* threshold whose **bar does not rise with `N`**. 2-of-3 and 2-of-10
are the same bar.

This shipped. `verify_pinned_root` and `verify_lineage_root` had it while `anchored_state`, which
carries a value, was correct on byte-identical input — so the two calls the read-path pin actually
makes were the two without the property, and three endpoints with one a generation behind served
stale content with no attacker involved.

Three things worth carrying forward:

* **A tri-state at the source beats classifying an error string.** `Verdict::{Confirmed, Rejected,
  Unreachable}` is decided where the evidence exists: the lineage walk already separated the cases
  structurally (a completed walk missing the root is a rejection; a failed walk is unreachable), and
  the bounded pin needed one extra reachability probe on the failure path only.
* **Arrange the remaining ambiguity to fail in the refusing direction.** That probe races the call it
  classifies. If the chain drops in between, a genuine unreachability is recorded as a rejection —
  which refuses. The opposite error fails OPEN, and is the defect being removed.
* **The dangerous half was the COMPOSITION.** `content_serve.rs`, `dig_rpc/dispatch.rs` and
  `module_reshare.rs` all treat a failed tip resolution as the #747 broken-walk case and fall back to
  `verify_pinned_root`. Widening what the tip's `Err` MEANS routed the strongest signal the feature
  produces onto the one check that could not hear it. Whenever an existing error value gains a new
  meaning, re-read every arm that already matches on it — the arm was written against the old set.

## Test the configuration that separates the semantics, not the one that is easiest to script

Every verification test here scripted only an unreachable source. That fixture cannot distinguish a
dissent rule from a threshold rule, because under both an unreachable voice is dropped — so the
defect above was untested rather than tested-and-wrong. The missing fixture was one sentence long: a
voice that is REACHED and says no.

Ask what the nearest wrong implementation is, then ask which input it would answer differently on. If
no fixture in the suite is that input, the property is undefended however many tests surround it.
