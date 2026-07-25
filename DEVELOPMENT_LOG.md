# Development Log — dig-node

High-signal realizations from debugging/development: non-obvious cross-system couplings,
sharp edges, and gotchas. Concise durable facts with context — NOT a change diary. See
`CLAUDE.md` §4.5 for the maintenance contract (a curator periodically re-verifies + prunes).

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
