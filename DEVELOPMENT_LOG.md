# Development Log — dig-node

High-signal realizations from debugging/development: non-obvious cross-system couplings,
sharp edges, and gotchas. Concise durable facts with context — NOT a change diary. See
`CLAUDE.md` §4.5 for the maintenance contract (a curator periodically re-verifies + prunes).

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
