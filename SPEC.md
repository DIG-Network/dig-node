# dig-node — Normative Specification

This document is the authoritative contract for the **dig-node** repository: the **canonical DIG
node**. dig-node OWNS the node implementation directly — the JSON-RPC dispatch, local-first
content serve/fetch/redirect, chain-anchored-root resolution, chain-watch, subscription
management, generation gap-fill, the cache, and the peer-to-peer (P2P) stack. It ships two host
shells around that one node implementation: a self-contained cross-platform binary installable as
an OS service (Windows SCM, Linux systemd, macOS launchd), and an in-process cdylib the DIG
Browser links. This document specifies identity and naming, the environment/configuration
contract, the HTTP/JSON-RPC surface, the control plane, the CLI contract, the OS-service
lifecycle, and the release-asset contract.

The **DIG read protocol wire shapes** (the `dig.getContent` ciphertext + Merkle-proof shapes, the
URN grammar, anchored-root semantics, the §21 sync protocol) are the canonical DIG-node RPC
interface defined in the `dig-rpc-protocol` crate and specified on the docs.dig.net Protocol pages.
For the `.dig` STORE FORMAT itself (byte layout, read/verify/decrypt, chain anchoring) dig-node
depends on digstore's store-format LIBRARY crates. This document references those contracts; it
does not restate them (§2.2, §5).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in RFC 2119.

For usage instructions, see `README.md`. For non-normative narrative, see `USER_JOURNEY.md`.

---

## 1. Scope and architecture

1.1. dig-node is the **canonical node**, organized as a Cargo workspace of four crates:

- **`dig-node-core`** (library, `dig_node_core`) — the NODE engine itself. It owns `handle_rpc`
  dispatch, local-first content serve/fetch/redirect, chain-anchored-root resolution, chain-watch +
  subscriptions + generation gap-fill, the cache, and the P2P stack (peer serve/dial, DHT
  provider records, PEX, multi-source download). It depends on the P2P crates
  (`dig-nat`/`dig-gossip`/`dig-dht`/`dig-pex`/`dig-download`/`dig-peer-selector`) — consumed from
  crates.io per §3.6, with the single exception of `dig-gossip`, which stays a pinned git
  dependency until its crates.io publish is unblocked (guarded pending `dig-peer-protocol`, #681) —
  and on digstore's `.dig` store-format LIBRARY crates
  (`digstore-core`/`-crypto`/`-chain`/`-host`/`-remote`/`-stage`) as git dependencies. The
  dependency direction is dig-node-core → store-lib; digstore MUST NOT depend on dig-node-core
  (digstore is only ever an RPC client of a node). The engine library is named `dig-node-core` so
  it no longer shares a name with the `dig-node` binary the service shell produces (#216).
- **`dig-node-service`** (binary `dig-node`) — the OS-service host shell around the engine library.
- **`dig-runtime`** (cdylib `dig_runtime`) — the DIG Browser's in-process host shell (§15).
- **`dig-wallet`** (library + binary) — the DIG Browser's built-in Chia wallet host.

1.2. The **service shell** (`dig-node-service`) owns exactly:

- HTTP transport (axum): listeners, CORS, Host-header allowlist (§4);
- request **normalization** (param-name aliasing only, §5.3);
- the **opt-in passthrough relay** to a configured upstream DIG RPC for methods the node does not
  resolve — OFF by default, and never to itself (§5.4);
- the **discovery surface** (`/health`, `/version`, `/openrpc.json`,
  `/.well-known/dig-node.json`, `rpc.discover`) (§6);
- the **control plane** (`control.*`) with its local-token authorization (§7) — the operator
  surface (status/hostedStores/sync/config/cache); control methods it does not own are delegated
  to the node's own control surface (peerStatus/subscribe/unsubscribe/listSubscriptions);
- the **CLI** and OS-service registration (§8, §9);
- two small pieces of persisted state in the shared `config.json`: the pin registry and the
  upstream override (§7.6).

The service shell MUST NOT reimplement, transform, or "improve" the node's responses: what
`dig_node_core::handle_rpc` returns is what the client receives.

1.3. The wire contract is byte-identical across BOTH host shells because dispatch IS the same
`dig_node_core::handle_rpc` in both — the OS-service binary AND the `dig-runtime` cdylib's `dig_rpc`
export run ONE node implementation. (The DIG Browser itself starts the cdylib WALLET-ONLY (§15) and does
NOT run this in-process node — it is a pure RPC consumer of an EXTERNAL node over the §5.3 ladder; the
`dig_rpc` full-node path is for other consumers.) A client written against `rpc.dig.net` (e.g. the DIG
Chrome extension's `fetchContentViaRPC` pipeline) MUST work against this node unchanged. Verification and
decryption happen in the **client** — for the DIG Browser via the native read-crypto FFI (§15.1), for
webpages via the equivalent `dig-client-wasm`; the node serves blind ciphertext + proofs and MUST NOT
return plaintext for content reads. The ONE exception is the loopback-only local plaintext
content-serve surface (§4.6) — a DISTINCT HTTP surface from this JSON-RPC read plane — which decrypts
SERVER-SIDE for a same-machine browser over loopback; the JSON-RPC `POST /` read plane, `rpc.dig.net`,
and every peer surface stay blind ciphertext + proof.

1.4. **Canonical RPC interface — `dig-rpc-protocol` + `dig-rpc`.** The RPC surface this node exposes
(method names + request/response types, the error-code taxonomy, and the tier classification) is
the canonical DIG-node RPC interface defined ONCE in the **`dig-rpc-protocol`** crate (published on
crates.io; formerly `dig-rpc-types`) — the single source of truth this node (the one implementation
shared by both host shells) and the `rpc.dig.net` gateway share, so the two can never drift. The
JSON-RPC server framework (transport surfaces, tier allowlist enforcement, rate limiting, mTLS) is
the **`dig-rpc`** crate, which depends only on `dig-rpc-protocol`. This
SPEC's method catalogue (§5.5), envelope rules (§5.1), and error catalogue (§10) MUST match
`dig-rpc-protocol` exactly; where they differ, `dig-rpc-protocol` is authoritative and this SPEC is
the drift to fix. The OpenRPC document (§6.3) is generated from `dig-rpc-protocol`'s own
method/tier/error tables.

1.5. **dig-rpc-protocol adoption status.** `dig-rpc-protocol` is published on crates.io (0.3.0) and
this repo DEPENDS on it (#1075): `dig_node_core::handle_rpc` dispatches on `Method::from_name` + the
`Method` enum (not string literals), and the mTLS peer-reachability allowlist is
`Method::is_peer_reachable` — the single allowlist source both node implementations share (the #179
auth-bypass surface). The dig-node-service discovery catalogue (`meta.rs`) is a SUPERSET (it adds the
shell's HTTP control surface — pairing/control.status/hostedStores/updater — and the `served`/
`requires_auth` model that the node↔node `Method` crate deliberately does not model); a drift guard
ties its node-surface method names + the peer-reachable set to the crate. The shell keeps its own
`ErrorCode` enum, but every code it shares with the crate now SOURCES its number and machine string
from `dig_rpc_protocol::ErrorCode` rather than restating them, and a guard asserts that equality
across the whole shared set. One shell-specific string remains: `DISPATCH_FAILED` at `-32000`, where
the crate says `SERVER_ERROR`. That name is minted and published by the shell alone, so reconciling
it is a separate, wire-visible decision. Not yet adopted: the crate's `RpcError` envelope type and
the `dig-rpc` server framework. The numeric error codes remain guaranteed
identical by the conformance vectors.

---

## 2. Identity and naming

2.1. **Canonical name.** The produced binary, the service-shell Cargo package (`dig-node-service`),
the OS service, and every machine-readable service-identity surface are named `dig-node`. The node
ENGINE library crate is `dig-node-core` (lib `dig_node_core`) — a distinct name from the `dig-node`
binary so the two are never confused (#216). Every machine-readable surface (`/health.service`,
`/version.service`, the CLI `--json` envelopes' `service` field) MUST report the service identity
string `"dig-node"` (`meta::SERVICE_NAME`) — the alias below renames only the invoked binary, never
the service identity.

2.1a. **`dign` first-class alias (issue #548).** The service shell also produces a second binary,
`dign`, a FIRST-CLASS alias for `dig-node` (mirroring how `digs` aliases `digstore`, #434). It is a
real installed binary — not a shell alias — defined as a second `[[bin]]` target
(`crates/dig-node-service/src/bin/dign.rs`) that shares the SINGLE entrypoint
`dig_node_service::run()` with `dig-node`, so there is NO duplicated logic. `dign <args>` MUST behave
IDENTICALLY to `dig-node <args>`: the same subcommands, flags, `--json` envelopes, and exit codes.
The displayed program name is derived from arg0, so `dign --help`/`--version` report `dign` while
`dig-node --help`/`--version` report `dig-node`. A release publishes `dign` alongside the primary
under the stem `dign-<ver>-<os>-<arch>[.exe]` (byte-identical shape to `dig-node-<ver>-<os>-<arch>`).

2.2. **One canonical version field (HARD RULE).** The node reports exactly ONE version — the
`version` field (the shipped `dig-node` binary / workspace release version, `meta::VERSION`) —
across `/version`, `/.well-known/dig-node.json`, and `control.status`; `commit` (`meta::GIT_SHA`)
pins the exact source revision beside it. There is NO second version key: the former
`dig_node_version` (the internal engine-library crate version, `dig_node_core::NODE_VERSION`) was
removed in #585/#586 because it named a *different* value under a second key — ambiguous ("which
version?") — and `commit` already fingerprints the now-in-repo engine. The node engine
(`dig-node-core`) is a first-party sibling crate in this workspace; when its crate version changes,
or when the digstore store-format git dependencies (`digstore-*`) are bumped to a new rev, the
method catalogue MUST be re-verified against the node's real dispatch (the drift guard, §5.6,
enforces this).

2.3. **Protocol tag.** `meta::PROTOCOL` is the DIG read-protocol identifier (`"21"`, the
rpc.dig.net §21 JSON-RPC read contract). It MUST be bumped only when the wire contract changes.

2.4. **Service label.** The OS-service label is the reverse-DNS constant
`net.dignetwork.dig-node` (`service::SERVICE_LABEL`). On Windows it becomes the SCM service name
(qualified form `net-dignetwork-dig_node`); on launchd, the plist label; on systemd, the unit
name. It MUST remain stable: `install`, `uninstall`, `start`, `stop`, and the Windows service
dispatcher registration (§9.4) all address the service by this exact label.

2.5. **Build provenance.** `build.rs` embeds the short git SHA of HEAD at compile time as the
`DIG_NODE_GIT_SHA` compile-time env var (surfaced as `commit` in `/version`, `/health`,
`/.well-known/dig-node.json`, and `control.status`). Outside a git checkout the value MUST be the
literal string `"unknown"`; the build MUST NOT fail for lack of git.

2.6. **Legacy reference implementation.** The `node/` directory contains the retired v0.2
JavaScript server (`@dignetwork/dig-companion`), retained as documentation only. It is NOT a
shipped artifact and carries no conformance obligations.

---

## 3. Configuration — the environment contract

Configuration is resolved from the process environment by `Config::from_env()` at startup.

### 3.1. Stable `DIG_NODE_*` names (HARD RULE)

The bind variables are named **`DIG_NODE_PORT`** and **`DIG_NODE_HOST`**. These are the binary's
stable configuration contract: the dig-installer sets them and apt.dig.net documents them. They
MUST NOT be renamed again — DIG is pre-release with no legacy aliases (#201); the canonical names
ARE `DIG_NODE_*`, full stop.

### 3.2. Variables and defaults

| Variable | Meaning | Default | Rules |
|---|---|---|---|
| `DIG_NODE_PORT` | localhost-listener bind port | `9778` | Parsed as `u16`; `0`, unparsable, or unset → default. |
| `DIG_NODE_HOST` | EXPLICIT localhost-listener bind IP override | *(unset)* | Parsed as `IpAddr`; unparsable/blank/unset ⇒ unset (§4.1's dual-stack default — see below), NOT a hardcoded `127.0.0.1` default. Setting it REPLACES the dual-stack default with exactly that one address (#288). A NON-loopback value is REFUSED at startup unless `DIG_NODE_ALLOW_REMOTE` is truthy (§3.2.1, #1662). |
| `DIG_NODE_ALLOW_REMOTE` | permit a non-loopback `DIG_NODE_HOST` bind | `false` | Truthy = `1`/`true`/`yes`/`on`; anything else (unset/blank/falsy/unrecognized) ⇒ the security-safe default **false**. When false, a non-loopback `DIG_NODE_HOST` is a fatal configuration error at startup (§3.2.1). Loopback overrides and the no-override default never require it. |
| `DIG_RPC_UPSTREAM` | upstream DIG RPC base URL for passthrough + miss-proxy | *(unset — NO default upstream)* | Normalized (§3.3); highest precedence (§3.4). Unset ⇒ passthrough is OFF and an unimplemented method answers a local `-32601` (§5.4). A value naming THIS node is REFUSED (§3.4.1). |
| `DIG_NODE_CACHE` | explicit on-disk `.dig` cache dir | *(unset)* | Blank/whitespace ⇒ unset. Unset ⇒ shared canonical default (§3.5). |
| `DIG_NODE_DIGLOCAL` | toggle for the bare `dig.local` listeners (`http://dig.local` on `127.0.0.2:80` AND, when a dig-cert leaf is present, `https://dig.local` on `127.0.0.2:443` — §4.1a) | `true` | Off = `off`/`disabled`/`0`/`false`/`no`; on = `on`/`enabled`/`1`/`true`/`yes`; case/whitespace-insensitive. Unset or EMPTY ⇒ **default true**. An UNRECOGNIZED value ⇒ default true AND a warning naming the variable, the rejected value and the applied default (see **Capability-flag vocabulary and failure direction**). |
| `DIG_NODE_PROFILE_SYNC` | operator kill switch for profile-body sync (opcodes 223/224/225, §22) | `true` | Off = `off`/`disabled`/`0`/`false`/`no`, case- and whitespace-insensitive; unset, empty or unrecognized ⇒ **default true**. Off means the node neither fetches nor serves profile bodies; nothing else depends on it, so it is a clean degradation. |

The default port is the UNCOMMON high port **`9778`** (not `80`/`8080`). Port 80 requires elevation
on most OSes, and both `80` and `8080` are the collision-prone common-dev ports most likely already
bound on a developer machine; `9778` is deliberately clear of the common-dev set
(80/443/3000/5000/8000/8080/8888/9000) and well-known service ports. It is the sibling of the
dig-wallet HTTP API's `9777` (wallet `9777`, node `9778`) and matches the local-node port the
digstore §5.3 resolver already expects (`DEFAULT_LOCAL_NODE_PORT`). Every consumer of the §5.3
`localhost` tier — the DIG Chrome extension's `server.host` default, the dig-installer, and the DIG
Browser — MUST target `localhost:9778` to match. `DIG_NODE_PORT` overrides it; the `http://dig.local`
listener (`127.0.0.2:80`) is unaffected — only this localhost port changed (#132).

### 3.2.1. Loopback-only enforcement (HARD RULE, #1662)

The local RPC/content API bind is loopback-only by default AND that property is ENFORCED, not
merely assumed. The node MUST refuse to start when `DIG_NODE_HOST` resolves to a NON-loopback
address unless `DIG_NODE_ALLOW_REMOTE` is truthy: an unauthorized non-loopback override is a fatal
startup configuration error with a clear message naming the escape hatch. This makes the service's
"loopback-only / never peer-reachable" invariants TRUE rather than asserted — the local API is
never silently exposed to the network from an unenforced config assumption.

- **Loopback** = an IPv4 loopback (`127.0.0.0/8`), the IPv6 loopback (`::1`), or an IPv4-mapped IPv6
  loopback (`::ffff:127.0.0.1`). All are accepted without the flag.
- **Escape hatch** — `DIG_NODE_ALLOW_REMOTE=1` (truthy per the table) permits a deliberate
  non-loopback bind (e.g. a remote-API test rig). This is opt-in only; it is never on by accident.
- **Scope** — this governs ONLY the local RPC/content bind ([`Config::bind_addr`]). The peer P2P
  wire (mTLS, dig-node-core) and the loopback wallet mTLS listener bind independently, so
  enforcement never affects peer connectivity.
- **Install-time fail-fast (#1667)** — the SAME refusal is applied at `dig-node install`: an
  unauthorized non-loopback `DIG_NODE_HOST` is rejected with the identical error BEFORE the service
  is registered, so an operator learns of the misconfiguration immediately instead of installing a
  service that fails closed on its first start.

The variables above are the shell's public bind/upstream/cache knobs. The node ENGINE library
(`dig-node-core`) additionally reads the following variables directly from the environment; the shell
does not own them (except `DIG_NODE_UPSTREAM`, which the shell SETS — see below):

| Variable | Meaning | Default | Rules |
|---|---|---|---|
| `DIG_NODE_CACHE_CAP` | LRU cache size cap, in bytes | `1073741824` (1 GiB) | Parsed as `u64`. Consulted ONLY when the persisted `cache_cap_bytes` key in `config.json` is absent or `0` (the persisted value wins). Unparsable/unset ⇒ default. |
| `DIG_NODE_COINSET` | override the coinset API base used for chain-anchored-root resolution | `https://api.coinset.org` (mainnet) | Blank/unset ⇒ mainnet default. Used for tests / alternate endpoints. |
| `DIG_NODE_CHAIN_ENDPOINTS` | comma-separated coinset-protocol endpoints the anchored root is CORROBORATED across (§14.4b) | unset (single-source) | Two or more INDEPENDENTLY-HOSTED endpoints enable the agreement rule; independence is derived from resolved addresses, so two names for one machine stay ONE voice. Unparseable entries are DROPPED, never defaulted. Prefer three or more. Takes precedence over `DIG_NODE_COINSET`. |
| `DIG_NODE_PIN` | read-path anchored-root pin enforcement (§14.4) | `on` (ENFORCED, fail-closed) | ONLY `off`/`0`/`false` disable the node-side pin (a named offline/local-dev escape hatch); any other value or unset ENFORCES. Clients still verify proofs against their own trust root regardless. |
| `DIG_NODE_WATCH_INTERVAL` | chain-watch poll interval, in seconds (§14.2) | `30` | Parsed as `u64`; `0`/unparsable/unset ⇒ default `30`; floored at `1` s so a mis-set value cannot flood coinset. |
| `DIG_NODE_UPSTREAM` | **INTERNAL** — the effective upstream the node library reads | *(unset — NO default upstream)* | NOT a user knob. The shell resolves the upstream (§3.4) and writes this via `Config::apply_to_env()` (§3.5); the shell's public knob is `DIG_RPC_UPSTREAM`. Empty ⇒ the library makes no upstream request at all. |
| `DIG_WALLET_WC_PROJECT_ID` | initial/default WalletConnect projectId for the wallet host (§16) | *(unset ⇒ none)* | A persisted `wc_project_id` in `config.json` wins over this; a blank persisted value falls through to this env. Blank ⇒ treated as unset. |
| `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC` | outgoing-bandwidth throttle cap, in bytes/second (§17) | `0` (UNLIMITED — opt-in) | Parsed as `u64`; `0`, unparsable, or unset ⇒ unlimited (the throttle is a no-op until an operator configures a cap). Resolved ONCE at node construction. |

### The shared off-token

`DIG_PEER_NETWORK`, `DIG_RELAY_URL` and `DIG_BOOTSTRAP_PEERS` are the three knobs that decide whether
this node reaches the network at all. All three read ONE off-vocabulary: **`off`, `disabled`, `0`,
`false`, `no`, or an explicitly empty value** — trimmed and case-insensitive. Any of those disables
the knob; anything else does not.

A node MUST NOT accept a disable token on one of these knobs and ignore the same token on another.
An operator who writes `OFF` and gets an isolated relay but a live peer network has been told the
switch worked when it did not.

An explicitly EMPTY value counts as a disable on all three, for the reason given under
`DIG_BOOTSTRAP_PEERS` below: a variable set to nothing is an operator saying "none", and resolving
it to the compiled-in default makes a node believed to be isolated dial production infrastructure.
An UNSET variable is a different thing and keeps its documented default.

An unrecognised value is NOT a disable. For `DIG_RELAY_URL` an unrecognised value is a relay URL, so
reading one as a disable would silently unplug a configured relay.

The peer-network layer honors `DIG_PEER_NETWORK` (disable the L7 peer network) and `DIG_RELAY_URL`
(override or disable the relay), which gate the P2P bring-up, and
**`DIG_PEER_PORT`** — the mTLS peer-RPC server listen port (dig-node-to-dig-node RPC traffic, §5.2).
Parsed as `u16`; unparsable/unset ⇒ the default **`9444`** (`peer::DEFAULT_P2P_PORT`).
Bound dual-stack IPv6-first with an IPv4 fallback, per §5.2.

**`DIG_BOOTSTRAP_PEERS`** — the always-on peer anchors dialled at startup, as a comma-separated
`peer_id@host:port` list. `off`/`disabled` (case-insensitive) and an explicitly EMPTY value each opt
out entirely; an UNSET variable falls back to the canonical compiled-in set.

Set-but-empty MUST mean "no anchors", distinguishably from unset. A node configured for isolation
(`DIG_BOOTSTRAP_PEERS=` with `DIG_RELAY_URL=off`) MUST NOT dial the compiled-in anchor: an isolated
node that silently gains an outside peer has a peer pool that is not the one its operator configured,
so every metric computed over pool membership is quietly wrong rather than obviously broken.

An operator SHOULD write `off`, not an empty value. The two are equivalent to this node, but an
empty value is not equivalently DURABLE across the tooling that carries it: on Windows an empty
environment variable is deleted rather than emptied, so it arrives UNSET and therefore resolves to
the public compiled-in anchor. The failure is silent and inverts the experiment — an "isolated"
node reaches production and the run passes for the wrong reason. `off` is a non-empty token that
survives every carrier and cannot degrade that way, which is why the shipped
`/etc/dig-node/dig-node.env` uses it.

The canonical set is `dig_constants::DIG_BOOTSTRAP_PEERS` and MUST NOT be re-declared here. It names
the PEER interface host `node-rpc.dig.net:9444` — NOT `rpc.dig.net`, which is a CloudFront
distribution that terminates HTTPS, cannot carry the mTLS peer protocol, and whose peer ports are
closed. `rpc.dig.net` appears in this system only as the §5.3 client→node READ gateway
(`RPC_DIG_NET_URL`); the two roles MUST NOT be collapsed.

A bootstrap anchor exists because every other peer input presupposes a peer the node already has:
peer exchange spreads what a live link's far end knows, the DHT answers through peers already in the
table, and a relay reservation only makes this node reachable. Normative properties:

- Each entry MUST carry a 64-hex `peer_id`, pinned as `SHA-256(TLS SPKI DER)`. An entry without one
  is SKIPPED, never dialled unpinned — dialling unpinned would accept whatever identity answered at
  that address, which is what the pinning exists to deny. A malformed entry is dropped without
  discarding its well-formed neighbours.
- Dials are IPv6-first with an IPv4 fallback, per §5.2, and run the full traversal ladder.
- An anchor is an UNTRUSTED peer (NC-12). Being well-known is not being trusted: it acquires no trust
  flag, bypasses no corroboration, and counts as exactly one voice — identical in every respect to a
  peer learned by exchange.
- Bring-up MUST NOT block on or fail from a bootstrap dial. A node whose anchors are all unreachable
  MUST still start and still operate from relay- and exchange-discovered peers; a hard dependency
  would make one host a single point of failure for every fresh node in the network.

**`DIG_GOSSIP_PORT`** — the gossip pool listen port (distinct from the mTLS peer-RPC port above, #871).
Parsed as `u16`; unparsable/unset ⇒ the default **`9445`** (`peer::DEFAULT_GOSSIP_PORT`).
The peer-RPC (9444) is the node's advertised peer-network identity and the route peers dial to fetch
content; the gossip pool (9445) is the internal connection manager for the node's own peer pool. Both
bind dual-stack IPv6-first with an IPv4 fallback, per §5.2. Both of these **chia-ssl** listeners MUST
present the node's persistent `NodeCert` identity, so the direct-gossip pool's inbound TLS listener
hashes to the SAME `peer_id = SHA-256(TLS SPKI DER)` the node registers/advertises/pins on :9444 — the
gossip pool loads its cert/key from the NodeCert files rather than minting its own, or a direct dial to
this node fails closed with a `peer_id mismatch` (#1532). This unification covers the chia-ssl path
(:9444 peer-RPC + :9445 direct-gossip listener) ONLY; the dig-nat / DigPeer NAT-traversal transport
(the relayed + hole-punch tiers) carries its OWN transport identity, which is unified with the
persistent NodeCert SEPARATELY under #1541 — until that lands, the NAT-traversal path presents an
ephemeral peer_id.

**Network identity — `DIG_NETWORK_GENESIS` + `DIG_NETWORK_ID`.** The node resolves TWO coupled
network identities:

- The **gossip `network_id`** — the L2 genesis challenge (`Bytes32`) the connected pool, DHT, and PEX
  key on. It is `DIG_NETWORK_GENESIS` (a valid non-zero 64-hex value) when set, else the canonical
  `DIG_MAINNET` genesis (a REAL non-zero Chia mainnet header hash pinned in `dig-constants`; a blank,
  non-hex, wrong-length, or all-zero value falls back to it). It MUST be non-zero or `dig-gossip`
  rejects the config at start.
- The **effective network label** — the STRING namespace advertised to the relay introducer + relay
  reservation and reported by `control.peerStatus` / `dig.getNetworkInfo` as `network_id`. Resolved in
  precedence order: an explicit **`DIG_NETWORK_ID`** wins; otherwise, when `DIG_NETWORK_GENESIS`
  selects a NON-default genesis, the label is DETERMINISTICALLY DERIVED from that genesis (`DIG_` + the
  first 16 hex chars of the genesis), DISTINCT from `DIG_MAINNET` and distinct per genesis; otherwise
  it is byte-identical **`DIG_MAINNET`**. Deriving the label from the genesis keeps a
  `DIG_NETWORK_GENESIS`-isolated dev/test network genuinely isolated at discovery (it neither joins nor
  is joined to the mainnet introducer namespace), while the default (no override) MUST remain
  byte-identical `DIG_MAINNET` so mainnet peer discovery never forks.

The EFFECTIVE genesis (64-hex) is surfaced alongside the label in the `control.peerStatus` and
`dig.getNetworkInfo` status snapshots (the `genesis` field) so an operator can see the real network a
node is running on.

### 3.3. Upstream normalization

`normalize_upstream` MUST: trim whitespace, strip all trailing `/`, and prefix `https://` when the
value has no `http://`/`https://` scheme. An empty result is treated as unset.

### 3.4. Upstream precedence

The effective upstream is resolved in this order (first non-empty wins):

1. `DIG_RPC_UPSTREAM` env var — a deploy/CI override MUST never be silently overridden by a saved
   setting;
2. the persisted `upstream_override` key in `config.json` (written by
   `control.config.setUpstream`, §7.5);
3. **no upstream.** There is NO default upstream (#1997). A node that has not been given one
   does not have one, and MUST NOT relay to any host it was not configured with.

### 3.4.1. A node MUST NOT be its own upstream

A resolved upstream that names THIS node MUST be refused and treated as no upstream. Two
independent checks are required, because neither covers the other's case:

1. **Static (offline, at config resolution).** An upstream naming a loopback address, `localhost`,
   or `dig.local` on ANY port this node listens on MUST be refused. The check is stated over the
   CLASS of the node's own listeners — the configurable localhost port, `dig.local` plaintext `:80`,
   and the `https://dig.local` TLS pair on `:443` — not one member of it. A guard naming only `:80`
   lets `DIG_RPC_UPSTREAM=dig.local` through, because that normalises to `https://dig.local`.
2. **Runtime loop detection.** A public name may resolve back to this node through DNS, a CDN, or a
   gateway — invisible to any address comparison. At bring-up a node with a configured upstream MUST
   send it one ordinary `dig.health` request carrying a single-use random JSON-RPC `id`. If a request
   bearing THAT id subsequently arrives at this node's own dispatcher, the upstream demonstrably
   leads here and passthrough MUST be disabled for the life of the process.

The marker MUST travel in the JSON-RPC `id`, not an HTTP header: an intermediary that forwards
JSON-RPC bodies while dropping unknown headers (the rpc.dig.net gateway does exactly this) would
otherwise defeat the detection. A node MUST match only its OWN full probe id — matching the prefix
would let any caller disable a node's passthrough, and would misfire whenever this node is
legitimately somebody else's upstream.

### 3.5. Shared `.dig` cache

- Before constructing the node, the shell MUST call `Config::apply_to_env()`, which sets
  `DIG_NODE_UPSTREAM` to the resolved upstream (the node library reads that name internally;
  the shell's public knob is `DIG_RPC_UPSTREAM`), and sets `DIG_NODE_CACHE` **only when an
  explicit non-blank dir was configured**.
- When `DIG_NODE_CACHE` is unset, the shell MUST NOT invent a path: the read path resolves its
  shared canonical default (`%LOCALAPPDATA%\DigNode\cache` on Windows, `$HOME/DigNode/cache` on
  Unix/macOS) — byte-identical to the dir the DIG Browser's in-process node uses, so both
  installations share ONE cache. Writing an empty/derived value would break that sharing and is
  forbidden.
- The read path makes the shared dir safe for two processes (atomic content-addressed writes + a
  cross-process advisory lock); the shell relies on that and MUST NOT add its own cache-file
  locking.
- The **authoritative** effective cache dir + `shared` flag are those returned by the
  `cache.getConfig` RPC. The shell's `meta::cache_dir()` mirrors the canonical-path logic for
  discovery surfaces only; `meta::cache_shared()` MUST delegate to the read path's resolver
  (`dig_node_core::cache_dir_is_shared`), never reimplement the writability probe.

### 3.6. `config.json` co-tenancy

The shell persists its own keys (`pinned_stores`, `upstream_override`) in the read path's
`config.json` (path from `dig_node_core::config_path()`). Writes MUST be read-modify-write with an
atomic temp-file + rename in the same directory, and MUST preserve all keys the shell does not own
(e.g. `cache_cap_bytes`, `wc_project_id`).

---

## 4. HTTP transport

### 4.0a. The DIG loopback allocation (dig_ecosystem#767)

`127.0.0.0/8` is entirely loopback. DIG therefore takes its own addresses out of that range and
leaves `127.0.0.1` — the address every other program on the machine assumes it can have — alone.

| Address | Owner | Purpose |
| --- | --- | --- |
| `127.0.0.1` | **nobody — reserved for the rest of the machine** | MUST NOT be bound by a DIG service |
| `127.0.0.2` | dig-node | `dig.local` — the local content surface (`:80` plaintext, `:443` TLS) |
| `127.0.0.5` | dig-dns | the DNS responder (`:53`) and its HTTP gateway (`:80`) |

A new DIG loopback service MUST take a fresh `127.0.0.X` from this table rather than sharing an
allocated one, and MUST NOT bind `127.0.0.1` or a name that resolves to it. The table is
byte-identical with the `canonical` skill and `SYSTEM.md`; the three MUST agree.

**Why this is normative and not stylistic.** A DIG port on `127.0.0.1` collides with whatever
else on the host wants it, and the collision is a race rather than an error a user can read.
dig-node bound `127.0.0.1:9257` — Sage's own wallet RPC port — so after a reboot whichever
service won the race broke the other, and the user's symptom was `sslv3 alert handshake failure`
from a server they believed was Sage. That message names neither DIG nor a port conflict.

**IPv6.** These are IPv4-only control planes by design. §5.2's IPv6-first rule governs PEER
networking, where address family is a reachability question; a loopback control plane never
leaves the host, and IPv6 offers no equivalent of `127.0.0.0/8` (`::1` is a single address), so a
per-service v6 allocation is not expressible. A service MAY additionally bind `::1` as a SECOND
listener for clients whose resolver prefers v6, but `::1` is never the DIG-owned address.

**Ephemeral binds.** A short-lived local listener MUST attempt the DIG address first and MAY
fall back to `127.0.0.1` only where the DIG address cannot be bound at all — on macOS a
`127.0.0.X` alias other than `127.0.0.1` does not exist until `ifconfig lo0 alias` creates it. A
fall-back MUST be logged; a silent one is indistinguishable from the rule not being applied.

**Enforcement.** `tests/loopback_bind_guard.rs` fails the build on a new literal-loopback bind in
product source. It reads source text, so a bind of an address computed elsewhere is outside its
reach; every such site is enumerated in that test's declared-exception list with its reason.

### 4.1. Loopback listeners (dual-stack default, #91, #288)

The server opens UP TO THREE listeners for the SAME router:

1. **`<DIG_NODE_HOST>:<DIG_NODE_PORT>`** (default `127.0.0.1:9778`, §3.2) — always on. A bind
   failure here is FATAL (`serve` returns the error; CLI exit `BIND_FAILED`, §8.4).
2. **`[::1]:<DIG_NODE_PORT>`** (§5.2 dual-stack loopback) — the SAME `localhost:<port>` on the
   IPv6 loopback. Present ONLY when `DIG_NODE_HOST` is unset (the default): some resolvers return
   `::1` before `127.0.0.1` for `localhost` (Windows by default), so without this listener such a
   client cannot reach the node and observes it as offline even though the IPv4 listener answers.
   An explicit `DIG_NODE_HOST` override REPLACES the default dual bind with exactly that one
   address — this listener is then skipped, not added to. This bind is **best-effort**: on
   failure (IPv6 loopback unavailable/disabled) the node MUST log a structured warning to stderr
   and continue IPv4-only — it MUST NOT abort.
**Authority construction (§5.2, #1682).** Every socket authority the node binds, reports, or embeds
in a URL MUST be built from a typed address and port — never by concatenating the two as text. A
literal IPv6 address therefore always appears BRACKETED (`[::1]:9778`, `[2001:db8::1]:9778`), which
is what the socket-address and URL grammars require. `DIG_NODE_HOST` set to any IPv6 literal MUST
bind successfully; because a failure on listener 1 is FATAL, rendering that authority as unbracketed
text would make configuring the address family this ecosystem PREFERS a self-inflicted outage. This
governs the `/health` `addr` field, the `status` output, the control-client's JSON-RPC URL, and the
`open` command's browser-navigable candidate URLs equally.

3. **`127.0.0.2:80`** — the bare-`http://dig.local` listener (constants `DIG_LOCAL_IP` =
   `127.0.0.2`, `DIG_LOCAL_PORT` = `80`, `DIG_LOCAL_HOST` = `dig.local`). This bind is
   **best-effort**: on failure (no privilege, port in use, missing macOS `127.0.0.2` loopback
   alias) the node MUST log a structured warning to stderr and continue serving localhost-only —
   it MUST NOT abort. Skipped entirely when `DIG_NODE_DIGLOCAL` is falsy.

### Capability-flag vocabulary and failure direction

NORMATIVE. Complements **The shared off-token** above, which governs the isolation knobs; this governs the capability knobs.

A **capability flag** is a `DIG_*` environment switch that enables or disables a node capability and
holds no list. `DIG_WALLET_ENABLE_CHAIN_SYNC`, `DIG_NODE_DIGLOCAL`, `DIG_HOLDINGS_INGEST`,
`DIG_NODE_STORE_MELT` and `DIG_NODE_PROFILE_SYNC` are capability flags. `DIG_BOOTSTRAP_PEERS`, `DIG_RELAY_URL` and
`DIG_PEER_NETWORK` are **isolation** flags and are governed by **The shared off-token** above instead.

1. **One vocabulary.** Every capability flag MUST read the same off-tokens — `off`, `disabled`, `0`,
   `false`, `no` — and the same on-tokens — `on`, `enabled`, `1`, `true`, `yes` — each trimmed and
   compared case-insensitively. A flag that recognizes a token another flag rejects is non-conforming:
   an operator who learns a word works on one switch will use it on the next.

2. **An EMPTY value is ABSENT, not OFF.** A capability flag set to the empty string MUST take its
   default. This differs deliberately from an isolation flag, where an empty value names the empty list
   and MUST disable (see **The shared off-token**). A capability flag holds no list, and an empty value is what a shell
   produces from an unset expansion.

3. **Failure direction: fail in whichever direction cannot make a surface assert a falsehood.** An
   unrecognized value MUST NOT be resolved in a direction that lets any surface state something untrue.
   For a default-ON read path such as chain sync this means keeping the default: disabling it silently
   stops the replica advancing, and a stale replica's zero balance is indistinguishable from an empty
   wallet (§18.6). For an isolation flag the same principle requires the opposite resolution, because
   a node that keeps dialling reports an isolation it does not have.

4. **An unrecognized value MUST be disclosed.** The node MUST emit a warning naming the VARIABLE, the
   REJECTED VALUE, and the DEFAULT it applied, and MUST state that the operator's setting had no
   effect. A recognized value, including an absent or empty one, MUST NOT warn. Silence is what makes a
   typo indistinguishable from a deliberate omission, and it is the residue that survives whichever
   failure direction a flag takes.

The distinct loopback IP `.2` exists so the port-80 bind can never collide with an unrelated
`localhost:80` service. The dig-installer writes the hosts entry `127.0.0.2  dig.local`; this
listener is what makes the portless `http://dig.local` URL reach the node. No listener may
bind `0.0.0.0` or the IPv6 wildcard `[::]` — the node is a localhost endpoint and MUST never be
LAN-exposed. A service install (§9) forwards `DIG_NODE_HOST` into the installed service's
environment ONLY when the operator gave an explicit override, so a plain `dig-node install` with
no override yields a service that also dual-binds by default, rather than freezing an IPv4-only
default into every future install.

### 4.1a. Local HTTPS listeners — `https://dig.local` (#624, the #620 local-HTTPS epic)

Beside the plaintext loopback listeners (§4.1) the node serves the SAME router over TLS so
`https://dig.local` is a trusted origin in the browser. The certificate material is owned by the
`dig-cert` crate (per-machine, name-constrained local CA; see `dig-cert` SPEC) and PROVISIONED by
the dig-installer (#623); the node only READS the leaf to serve and OWNS leaf renewal.

The node opens UP TO TWO HTTPS listeners for the SAME router, both **gated on `DIG_NODE_DIGLOCAL`
being truthy AND a dig-cert leaf being present**:

1. **`127.0.0.2:443`** — the bare-`https://dig.local` listener (the IPv4 alias the installer's
   `127.0.0.2 dig.local` hosts entry resolves to). Best-effort: `:443` is privileged, so a bind
   failure (no privilege, port in use, missing macOS loopback alias) MUST log a structured warning
   and be non-fatal — the plaintext surface keeps serving.
2. **`[::1]:443`** — the IPv6-loopback sibling (§5.2). The leaf's SAN covers `::1`, so an
   IPv6-loopback client reaches the identical surface. Best-effort, non-fatal on bind failure.

**Fail-soft when no CA/leaf (HARD RULE).** When `dig-cert`'s TLS root has no `leaf.crt`/`leaf.key`
(the installer has not provisioned the CA yet), or the leaf cannot be loaded, the node MUST log an
informational line and serve **plaintext only** — HTTPS is NEVER a hard requirement to start. No
listener may bind `0.0.0.0` or `[::]`.

**Leaf rotation (the node is the runtime OWNER; SPEC §6.4 of dig-cert).** When HTTPS is up the node
drives `dig-cert`'s `RenewalManager::maintain` at service start and once daily. A pass re-issues the
leaf from `ca.key` once it is within 30 days of its 90-day lifetime, atomically swaps
`leaf.{key,crt}` (temp + rename, so no reader observes a torn or mismatched pair), and fires the
reloadable rustls resolver's `reload()` so the running listener presents the new leaf **without a
restart and without dropping connections**. Transient failures retry on a bounded backoff so a leaf
never lapses; the listener keeps serving the previous leaf until a pass succeeds. The daily interval
uses a **delay** missed-tick policy (#660): after a host sleep/suspend across several intervals the
node runs ONE catch-up pass (which fully reconciles the leaf) rather than bursting one redundant pass
per missed tick.

**TLS-root owner gate (#661, defence-in-depth).** Before reading ANY TLS material — the leaf to
serve, and `ca.key` on the renewal path — the node verifies the TLS root directory is privileged-owned
(§ the shared whole-path owner check) and **fails CLOSED to plaintext** otherwise. A user-writable TLS
root could hold an attacker-swapped `ca.key` that this privileged service would otherwise read and sign
with; refusing it removes that vector. The owner SID is read directly through the Win32 security API
(launching no process — the same spawn-free check the self-heal LPE gate uses), so the guard never
itself executes an attacker-planted binary.

**Shared whole-path owner check (#565/#661/#46, #712).** The three gates above defer to ONE shared
helper that classifies a directory as privileged-owned. It verifies the ENTIRE path, not just the leaf:
EVERY existing ancestor component (the directory, its parent, … up to the filesystem root) MUST be
privileged-owned AND MUST NOT be a symlink/junction/reparse point. A privileged-owned leaf under a
user-writable or symlinked ANCESTOR is still tamperable — an intermediate rename/replace is governed by
the parent's permissions, and a reparse point anywhere redirects the whole path — so a single weak
component fails the check. Per component: **unix** — owned by `root`/uid 0, no group/other write bit,
judged via `symlink_metadata` (lstat) so a symlink is rejected on its own identity; **Windows** — owner
SID equal (exact equality) to the well-known LocalSystem `S-1-5-18`, BUILTIN\Administrators
`S-1-5-32-544`, or `NT SERVICE\TrustedInstaller` (the fixed service SID that owns `C:\Program Files`
and its protected subtree — required so the canonical `%ProgramFiles%` install root is not
false-rejected), and the component carries no `FILE_ATTRIBUTE_REPARSE_POINT`. Fails CLOSED on any
indeterminate or missing component.

**The CA trust anchor is NEVER auto-rotated by the node.** An approaching CA expiry is only REPORTED
(`ca_renewal_due`); anchor rotation is an explicit, installer-coordinated `dig-cert rotate_ca` (it
re-installs trust into every store), never an automatic maintenance side effect. Only two operations
read `ca.key`: install (dig-installer) and leaf renewal (the node via `dig-cert`).

**Transition posture.** The plaintext `127.0.0.2:80` listener (§4.1) is KEPT — no redirect to HTTPS
yet — so existing plaintext consumers (extension/dig-dns/clients) do not break before the §5.3
https-first ladder migration ships. The TLS stack is pinned byte-identical to `dig-cert`/`dig-dns`
(`rustls` 0.23, `ring`, no aws-lc) so exactly one `CryptoProvider` is installed.

### 4.2. Host-header allowlist (anti-rebinding)

Every non-`OPTIONS` request MUST pass the Host allowlist before any handler runs. Allowed host
names (with or without a `:port` suffix): `dig.local`, `localhost`, `127.0.0.1`, `127.0.0.2`, and
the IPv6 loopback `::1` (bracketed `[::1]`/`[::1]:<port>` per RFC 7230's mandatory bracketing for
an IPv6-literal Host, or bare `::1` for a non-browser client that omits them, #288). A missing or
empty `Host` header MUST be allowed (HTTP/1.0, health probes). Any other Host — the DNS-rebinding
vector — MUST be rejected with HTTP **`421 Misdirected Request`** and a JSON-RPC error body
carrying the catalogued `INVALID_REQUEST` code (§10). `OPTIONS` (CORS preflight) is exempt so
preflights to allowed origins always succeed.

### 4.3. CORS

The CORS layer reflects two families of **loopback-trust origins** (the node binds loopback only;
CORS is not an auth boundary):

- **Local web/extension origins:** `chrome-extension://*` and `http://<host>[:port]` where `<host>`
  passes the §4.2 allowlist. `https://` for an arbitrary host and other schemes MUST NOT be reflected.
- **Desktop-app origins (#669):** the two canonical Tauri origins `tauri://localhost` and
  `https://tauri.localhost` (built-in, no configuration), plus any exact origin listed in the
  operator opt-in `DIG_NODE_CORS_APP_ORIGINS` (a comma/semicolon-separated allowlist). This lets a
  native app consuming `dig-urn-resolver` reach the node-first content tier. A desktop app runs on
  the same machine as the node, so this stays loopback-trust only and broadens no trust surface.

**CORS is scoped by route AND method (#702).** The reflection is decided per request, not once for
the router, and the two origin families have deliberately different reach:

- **Local web/extension origins** are reflected on the WHOLE HTTP surface.
- **Desktop-app origins** are reflected for **content reads ONLY** — a `GET` or `HEAD` to any route
  other than `/ws` and `/ws/status`. They MUST NOT be reflected for any other method on any route.
  This scoping governs `Access-Control-Allow-Origin` specifically, not the whole response: the
  remaining `Access-Control-*` headers are emitted by the CORS layer on any preflight it answers,
  independent of the origin verdict.

A preflight (`OPTIONS`) MUST be judged against the method declared in
`Access-Control-Request-Method`, not against `OPTIONS` itself, so the preflight answer matches the
answer the real request will receive. A preflight that declares no method MUST fail closed for the
desktop-app family.

Scoping by route alone MUST NOT be used, because it cannot express this policy: `POST /`
multiplexes content reads and the open wallet-read methods onto one JSON-RPC endpoint, and
`/{method}` serves the Sage-parity wallet RPC on `POST` and content on `GET`, so a route-keyed
decision must answer both traffic classes identically.

**Wallet-read exposure (#693) — now closed.** The open wallet-read methods (§7.2 / §18 `get_*`,
which carry no token) are reachable only by `POST`, so the split above removes desktop-app
cross-origin READ access to balances, addresses and coins. Custody was never in scope for it:
every wallet MUTATION and every `control.*` call stays token-gated (§7.12), and the bidirectional
wallet transport (`/ws`, §4.5/§4.8) validates `Origin` against only the local web/extension
subset, NEVER the desktop-app origins. The #669 contract is unchanged — a desktop app still
reaches the node-first content tier and still reads the exposed `X-Dig-*` provenance headers.

`Access-Control-Allow-Methods` MUST MIRROR the method the preflight declared, and MUST NOT
advertise a static method set. A static set is emitted on every answered preflight regardless of the
origin verdict, so an approved `GET` preflight from a desktop-app origin would also advertise
`POST` — seeding the browser's preflight cache with a `POST` entry that a later `POST /` then uses
to skip its preflight. Mirroring keeps the advertised method equal to the one the origin predicate
judged. The methods the router serves remain `GET`, `POST` and `OPTIONS`; allowed request headers
are `Content-Type` and `X-Dig-Control-Token`.

**Exposed response headers (#669).** The CORS layer MUST set `Access-Control-Expose-Headers` for the
`X-Dig-*` verification/provenance headers so a CROSS-ORIGIN browser client (dig-urn-resolver's
node-first path) can READ them — a cross-origin `fetch` can otherwise read only a short safelist, and
a resolver that cannot see `X-Dig-Verified` fails CLOSED and drops to the verified rpc tier. The
exposed set is: `X-Dig-Verified`, `X-Dig-Root`, `X-Dig-Inclusion-Proof`, `X-Dig-Chunk-Lens`,
`X-Dig-Source`, `X-Dig-Peer-Tier`, `X-Dig-Store-Id`, `X-Dig-Capsule`, `X-Dig-Resource-Key`,
`X-Dig-Owner-Puzzle-Hash`, `X-Dig-Generation`. These are read-only provenance metadata, so exposing them broadens only
readability. (Cross-repo contract with dig-urn-resolver — mirrored in `SYSTEM.md`.)

**Private Network Access (PNA, #285).** The server MUST advertise `allow_private_network` on the
CORS layer, so a preflight that carries `Access-Control-Request-Private-Network: true` gets
`Access-Control-Allow-Private-Network: true` back. Modern Chrome enforces PNA: any request from a
page or extension context to a private-network address (loopback included) is blocked unless the
preflight response carries this header — WITHOUT it, Chrome silently blocks every
extension→dig-node request and the extension (correctly, from its perspective) reports the node
OFFLINE even though the node is up and `/health` answers a direct, non-PNA-checked request. The
header is emitted ONLY on a preflight that itself requests it (tower_http's `CorsLayer` gates this
automatically); it never appears on an ordinary response and never changes the origin-reflection or
method/header-allow behavior above.

### 4.4. Routes

| Route | Method | Behavior |
|---|---|---|
| `/` | GET | Same body as `/health`. |
| `/` | POST | JSON-RPC endpoint (§5). |
| `/health` | GET | Liveness + identity + cache + methods (§6.1). |
| `/version` | GET | Build fingerprint (§6.2). |
| `/openrpc.json` | GET | The OpenRPC document (§6.3). |
| `/.well-known/dig-node.json` | GET | The discovery document (§6.4). |
| `/ws/status` | GET (WS upgrade) | WebSocket status/liveness channel (§4.5). |
| `/ws` | GET (WS upgrade) | Bidirectional wallet+control transport — correlated request/response + proactive push (§4.8). |
| `/{method}` | POST | Served Sage-parity wallet RPC (`POST {base}/{method}`, §18.1/§18.19). |
| `/{seg}` | GET | Root-absolute subresource rerooted via `Referer` into its store (§4.6). |
| `/s/<storeId>[:<root>]/<path>` | GET | Local plaintext content-serve — server-side decrypt (§4.6). |
| `/verify/<storeId>[:<root>]` | GET | Verification-ledger snapshot for a page session (§4.7). |
| *(fallback)* | GET | Root-absolute subresource rerooted via `Referer` into its store (§4.6). |

### 4.5. `GET /ws/status` — WebSocket status/liveness channel (#239)

A browser client (the DIG Chrome extension's service worker) that needs to react to the node
going offline/online AT ANY MOMENT — not just at the moment of its own next request — upgrades
this route to a WebSocket instead of polling `/health`. The **open socket is itself the liveness
signal**: a clean close, an abrupt reset, or a failed upgrade all mean "the node is not reachable
right now" to the client; there is no separate "are you alive" request/response on this channel.

**Origin validation (CSWSH defense).** Unlike `fetch`, a WebSocket handshake is not blocked by the
browser based on `Access-Control-*` response headers — a page from ANY origin can attempt
`new WebSocket(...)` against a listener the user's browser can reach. The server therefore
validates the `Origin` header itself, against the **local web/extension** subset of §4.3
(`chrome-extension://*` and an allowed local `http://` origin) — NOT the §4.3 desktop-app origins,
which are for the content-read surface only. A disallowed `Origin` MUST be
rejected `403 Forbidden` before the upgrade completes. A request with NO `Origin` header (a
non-browser client — a CLI, an integration test) MUST be allowed; the loopback-only bind is that
caller's defense.

**Message contract.** Every pushed frame is a JSON text frame carrying a discriminated `type`:

- **`status`** — sent EXACTLY ONCE, immediately on a successful upgrade. Fields: `type:"status"`,
  `service`, `version`, `commit`, `mode` (`"local-node"`), `addr`, `upstream`, `cache` (`dir` /
  `cap_bytes` / `used_bytes` / `shared`, identical shape to `/health`'s `cache` field), and `sync`
  (`{ "available": bool }`, whether a §21.9 identity is loaded — see §7.2). This is the SAME
  unauthenticated field set `/health` returns (`status_fields`, shared by both handlers so they can
  never drift) minus `/health`'s own `status:"ok"` and `methods` fields.
- **`heartbeat`** — pushed every ~5 seconds (`WS_HEARTBEAT_INTERVAL`) for the life of the
  connection: `type:"heartbeat"`, `ts` (unix milliseconds), plus a FRESH copy of the same
  service/version/commit/mode/addr/upstream/cache/sync fields as `status`. A heartbeat doubles as
  the "status changed" push — because it always carries a freshly-recomputed snapshot, any change
  (cache usage, sync availability) is visible to the client within one heartbeat interval; there is
  no separate change-detection mechanism in this version (the simplest thing that works).

Alongside each `heartbeat` text frame the server also sends a transport-level WS **Ping**. A
compliant WebSocket implementation (every browser; `tokio-tungstenite` on the Rust side) answers a
Ping with a Pong automatically at the protocol layer — this is invisible to page/service-worker
JavaScript (the browser `WebSocket` API never surfaces raw ping/pong frames to script), so it is a
belt-and-suspenders mechanism for the SERVER's own half-open detection, not something a browser
client can observe directly. If the server does not observe ANY frame from the client (a Pong or
otherwise) within `WS_PONG_TIMEOUT` (~20 seconds, 4x the heartbeat interval), it treats the
connection as half-open and closes it server-side (a clean WS Close), so the client's own
reconnect logic takes over. On receiving a client-initiated Close, the server MUST echo a Close
frame back (completing the WS closing handshake) before dropping the connection.

**Client responsibility (not specified here — see the consuming client's own SPEC.md).** Because a
browser's WebSocket API does not expose ping/pong to script, a client MUST judge liveness from the
`status`/`heartbeat` frames it actually receives: track the time since the last frame, and treat a
connection that has gone quiet for materially longer than the heartbeat interval as stale (close +
reconnect) even if the socket's `readyState` still reports open. A client SHOULD reconnect with
exponential backoff + jitter on any close/error and reset that backoff the moment a connection
succeeds again.

### 4.6. Local plaintext content-serve — `GET /s/<storeId>[:<root>]/<path>` (#289/#290)

A same-machine browser cannot present a client cert to obtain plaintext from the public gateway
(§5.3), so the LOCAL node — the trusted, key-holding, loopback-only endpoint — exposes a DISTINCT
HTTP surface that decrypts SERVER-SIDE and returns the real website. This is separate from the blind
JSON-RPC `POST /` read plane (§1.3, §5): plaintext crosses ONLY loopback; `rpc.dig.net` and peers
stay ciphertext-only.

**Route.** `GET /s/<storeId>[:<root>]/<path>` on every loopback listener (§4.1: `localhost:<port>`,
`[::1]:<port>`, and bare `http://dig.local`). `<storeId>` and the optional `<root>` are 64-hex; a
bare `/s/<storeId>[:<root>]/` (empty `<path>`) serves the store's default view `index.html`
(`DEFAULT_RESOURCE_KEY`). The Host allowlist (§4.2) + CORS (§4.3) answer only loopback names, so this
surface is never reachable off-machine.

**Resolution + verify + decrypt (fail-closed).** For `(storeId, path)` the node:
1. resolves `path` → `retrieval_key = SHA-256(canonical rootless URN)` (`urn:dig:chia:<storeId>[/<path>]`,
   empty → `index.html`) — byte-identical to `dig-client-wasm`/`dig-runtime`;
2. resolves the store's chain-anchored tip root and PINS the serve to it (§14.4, #127) — a requested
   root that is not the tip, an unconfirmable store, or an unreachable chain fails closed. A ROOTED
   request (`:<root>` present) anchors its pinned root by the singleton-lineage walk when that
   succeeds (which also yields the owner puzzle hash, §4.6 serve-metadata), but a walk aborted by a
   single unparseable intermediate generation (#747) falls back to a BOUNDED verify — one
   launcher-hint query reading only the current unspent generation (`verify_pinned_root`) — so a
   valid pinned root stays readable; both paths are fail-closed and enforce that the pinned root is
   the current on-chain generation. A ROOTLESS request resolves the tip via the walk and serves
   against it (surfaced as `X-Dig-Root` + `X-Dig-Verified: true`);
3. fetches the resource's ciphertext + inclusion proof + chunk lengths LOCAL-FIRST, then peer, then a
   CONFIGURED upstream if the operator set one (§4.6 cache order below; there is no upstream by
   default — §3.4 — so the ladder normally ends at peer and an unheld resource is a clean miss);
4. verifies `resource_leaf(ciphertext) == proof.leaf`, `proof.verify()`, and `proof.root ==
   chain_anchored_root`, THEN AES-256-GCM-SIV-decrypts each chunk under the per-URN key — the SAME
   `digstore-core` read-crypto every DIG client uses. A tampered chunk, decoy, or non-anchored root
   never decrypts.

**Store-root scoping (shared-origin best-effort).** Served HTML is rewritten with an injected
`<base href="/s/<storeId>[:<root>]/">` (RELATIVE links resolve within the store) and
`<meta name="referrer" content="same-origin">`. A ROOT-ABSOLUTE `/foo` request (the browser drops the
`/s/...` prefix) lands in the router fallback and is REROOTED via the same-origin `Referer` back into
its store; an unattributable root-absolute request is a `404` (asset) or the SPA fallback (route).
Absolute `https://…` URLs bypass the node entirely.

**SPA history-fallback + MIME rule (#144).** A route-like miss (`path` whose final segment has NO known
static-asset extension) serves the store's `index.html` (`200 text/html`) so a client-side deep link
boots. The node uses the store's `PublicManifest` (§5.5.1) to distinguish a KNOWN file genuinely missing
at this root (an honest `404`) from a route (the SPA fallback); a null manifest (old/private store)
degrades to the extension-less-path heuristic. An ASSET miss (a known non-HTML extension —
`js`/`mjs`/`css`/`json`/`wasm`/`svg`/images/fonts/media/…) is ALWAYS an honest `404`, never `text/html`
(a `text/html` body for a service-worker/module fetch is rejected by the browser for a wrong MIME type).

**Content-type + CSP.** The `Content-Type` is the ecosystem extension→MIME map (byte-identical to the
DIG loader's `contentType()`), with `X-Content-Type-Options: nosniff`. Served HTML additionally carries
a synthesized hardened store CSP (`object-src 'none'`, same-origin `base-uri`, un-framed, with the
sanctioned content network legs) attached as a response header, never trusted from the store body.

**Provenance headers (every serve, #292).** `X-Dig-Verified: true|false` (inclusion + chain-anchored-root
verified server-side — `false` only when the node-side pin is disabled via `DIG_NODE_PIN=off`),
`X-Dig-Root: <root>` (the resolved root served against), and `X-Dig-Source: local|peer|rpc` (the tier
that served the MAIN resource). A consumer's DIG Shields / toolbar reads these.

**Peer-tier attachment (every serve, #1763).** Every served response MUST additionally carry
`X-Dig-Peer-Tier: attached|unattached`, reporting whether the P2P content engine was attached at the
moment the read was ROUTED — i.e. whether Tier 2 was consultable at all. The node MUST capture this
once, before any tier runs, and report the same value regardless of which tier ultimately served the
bytes; it MUST NOT be derived from `X-Dig-Source`.

The two are independent and both are required, because `X-Dig-Source` alone cannot express the
difference between a gateway serve that MISSED on the peer tier and a gateway serve that never had
one. The node serves content from the moment its HTTP surface opens, which is BEFORE the peer network
attaches (§7.8) — availability is deliberately not traded away for readiness — so reads inside that
window skip Tier 2 entirely and fall to a configured upstream, or — with none, the default — MISS.
`unattached` is the node stating that;
a caller MUST NOT treat such a read as evidence about peer replication. `unattached` is also the
permanent value on the in-process/FFI path, which brings up no peer network.

`X-Dig-Peer-Tier` reports engine attachment ONLY: not peer count, not reachability, not whether a
fetch was attempted, and never verification (that is `X-Dig-Verified`).

**Serve-metadata headers (every serve, #486).** Alongside the provenance set, every served resource
carries: `X-Dig-Store-Id: <64-hex>` (the storeId serving this resource); `X-Dig-Owner-Puzzle-Hash:
<64-hex>` — the store's on-chain OWNER puzzle hash, resolved from the SAME chain read as the
anchored-root pin (§14.4) with no extra coinset call; **THE gate for tippability** — a consumer treats
a response carrying this header as tippable, one carrying no header as not; `X-Dig-Generation: <n>` —
the 0-based commit ordinal that last wrote the resource, per the store's embedded `PublicManifest`
(§5.5.1), a local-only lookup (never a chain call); `X-Dig-Capsule: <storeId:root>` — the capsule id
(the canonical `storeId:rootHash` pairing); `X-Dig-Resource-Key: <key>` — the resource/retrieval key of
the served resource (a bare/empty request normalizes to `index.html`, the resolved default view, never
an empty header value). All five describe the MAIN resource served; a value that is unknowable —
`X-Dig-Owner-Puzzle-Hash` when the chain-anchored pin did not run (`DIG_NODE_PIN=off`) or the resolver
could not supply it, `X-Dig-Generation` when the module carries no `PublicManifest` (an older `.dig` or
a private store) or lists no entry for the exact key — is OMITTED, never an empty placeholder. These
headers are attached ONLY on a genuine served resource (never on an error/`404`/non-DIG response), and
are present identically on a `HEAD` request to the same route (axum dispatches `HEAD` to the
registered `GET` handler and strips the body, so the full header set arrives with no body — no
separate HEAD code path).

**Local-first store cache (#290).** Resolution order per `(store, root)`:
1. a synced+verified `.dig` module on disk → serve LOCAL, no network (the DEFAULT once cached);
2. not held → serve the immediate resource from a peer (or a CONFIGURED upstream, if any) AND trigger a single-flight
   background whole-`.dig` sync-down (the deduped `maybe_backfill_capsule` → chain-anchored-root-pinned
   whole-store pull) into the reserved LRU cache dir, so the NEXT read is local. LRU eviction (§7.10)
   applies; an evicted-then-re-requested capsule re-syncs. Freshness is inherent to the anchored-root
   pin (§14.4): a stale locally-cached generation whose root is not the on-chain tip is NEVER served as
   current — the read resolves the tip and fetches/backfills that generation, so local-default is never
   local-FROZEN. A synced `.dig` is trusted only after it verifies against the on-chain root at serve.

**Salt.** A private store's secret salt is not yet provisioned to this surface; a private store therefore
fails closed at decrypt. Public stores (salt = none) serve fully. (Private-store salt provisioning is a
tracked follow-up.)

### 4.7. Verification ledger — `GET /verify/<storeId>[:<root>]` (#307)

The `/s/` serve path (§4.6) verifies every resource server-side against the store's chain-anchored root
and fails closed. The node RETAINS each per-resource verdict + the Merkle inclusion-proof data that verify
step computed, in a bounded, short-TTL, in-memory **verification ledger** keyed by `storeId:root`, and
exposes it read-only on the SAME loopback browser surface (same host-guard §4.2 + CORS §4.3 as `/s/`;
loopback-only, no secrets). A consumer (the DIG Chrome extension) reads it to render a page-level
"Verified by Chia" badge and a proof-inspection modal.

**Recording.** An entry is written on the EXISTING verify step (the ledger does NOT re-verify — it reuses
the proof the serve already computed), at each DEFINITIVE per-resource outcome:
- a resource served (`local`/`peer`/`rpc`) that verified → recorded with `verified` = the `X-Dig-Verified`
  result for that serve (`true` under the default chain-anchored pin; `false` only when `DIG_NODE_PIN=off`);
- an `rpc` response whose bytes were fetched but FAILED verification (a decoy / tamper / a root that is not
  the anchored tip) → recorded `verified: false` with a `failReason`, and — per fail-closed — NEVER served.

A tier fall-through (a `local` decoy that falls through to `peer`/`rpc`) and a genuine upstream content miss
(the `-32004` "resource not available") are NOT verification failures and are NOT recorded. Entries are
deduped by resource key (a re-served resource updates its entry in place, preserving load order).

**Bounds.** In-memory only, never persisted. Retained per `(store, root)` page session for a short TTL
(15 minutes since last update), capped at 64 sessions (least-recently-updated evicted) and 1024 resources
per session.

**Request.** `GET /verify/<storeId>[:<root>]`. `<storeId>` and the optional `<root>` are 64-hex (lowercased).
With `<root>` present the exact session is returned; with `<root>` omitted the store's most-recently-updated
session is returned (a page has one active root). A malformed path is `404`; any well-formed request is
`200` with a valid (possibly empty) JSON body.

**Response.** `application/json`, camelCase, stable field names:

```json
{
  "storeId": "<64-hex>",
  "root": "<64-hex>",
  "aggregate": {
    "verified": true,
    "anyRpcFailed": false,
    "counts": { "total": 3, "verified": 3, "failed": 0,
                "bySource": { "local": 2, "peer": 0, "rpc": 1 } }
  },
  "resources": [
    {
      "resourceKey": "index.html",
      "source": "local",
      "verified": true,
      "root": "<64-hex anchored root this entry served against>",
      "proof": {
        "leafHash": "<64-hex — SHA-256(resource ciphertext), the D5 leaf>",
        "siblings": [ { "hash": "<64-hex>", "dir": "left" }, { "hash": "<64-hex>", "dir": "right" } ],
        "leafIndex": 0,
        "proofRoot": "<64-hex — the root the proof folds to>"
      },
      "failReason": null
    }
  ]
}
```

**Aggregate rules (normative).**
- `aggregate.verified` = `resources` is non-empty AND every entry has `verified: true`. The badge is green
  "Verified by Chia" only when this is `true`; otherwise "Unverified".
- `aggregate.anyRpcFailed` = any entry with `source == "rpc" && verified == false`.
- `counts.total`/`verified`/`failed` count the entries; `counts.bySource` counts entries per tier.

**Proof-data semantics (for display + optional client re-verification).**
- `leafHash` = `SHA-256(resource_ciphertext)` — the per-resource Merkle leaf.
- `siblings` = the bottom-up inclusion path in fold order. `dir == "left"` means the sibling is the LEFT
  node (fold `hash(sibling, acc)`); `dir == "right"` means the sibling is the RIGHT node (fold
  `hash(acc, sibling)`). Internal-node hashing is domain-separated (`SHA-256("digstore:node:v1" || left || right)`).
- `proofRoot` = the root the proof folds to. A client re-verifies by folding `leafHash` up through `siblings`
  and checking it equals `proofRoot`, then checking `proofRoot == root` (the chain-anchored root). For a
  verified entry `proofRoot == root`; for a fail-closed entry they differ (and `failReason` explains why).
- `leafIndex` = the leaf's index reconstructed from the sibling directions (a left-sibling step sets the bit
  at that level). It is a DISPLAY value only — re-verification never consults it — and is exact for a leaf
  whose path has no odd-carry level.

### 4.8. `GET /ws` — bidirectional wallet+control transport (#369)

A thin client (the DIG Chrome extension) drives ALL wallet reads + `control.*`/wallet mutations over
ONE upgraded WebSocket instead of per-call HTTP, and the node PROACTIVELY PUSHES sync-status
transitions + sync events on the same socket — subsuming the SSE `SyncEvent` stream (§18.14) and
`get_sync_status` polling. This is the wallet+control channel ONLY; the resolver/content transport
(§4.6, JSON-RPC §5) is UNCHANGED.

**Origin validation (CSWSH).** Identical to §4.5: the `Origin` header is checked against the local-origin
allowlist (`chrome-extension://*` + allowed local `http://`); a disallowed browser `Origin` is rejected
`403` before the upgrade. No `Origin` (a non-browser client) is allowed (loopback bind is the defense).

**Frames are JSON text frames.** Client→node frames carry a discriminated `type`:

- **`request`** — `{ "type":"request", "id": <string|number>, "method": <string>, "params": <object>,
  "token": <string?> }`. `id` correlates the response. `method` is any served wallet method (Sage
  snake_case) or a `control.*`/`pairing.*` method. `params` is
  the method's request object (the Sage body for a wallet method). `token` is the paired/control token
  (§7.11/§7.12), required for gated ops (below).

Node→client frames:

- **`response`** — `{ "type":"response", "id": <echoed>, "ok": <bool>, "result": <json>?, "error": {
  "code": <int>, "message": <string> }? }`. `ok:true` carries `result`; `ok:false` carries `error`.
- **`sync_status`** (PUSH) — `{ "type":"sync_status", "state": "syncing"|"synced"|"disconnected",
  "peak_height": <u32>?, "target_height": <u32>? }`. Pushed ONCE immediately on connect (the initial
  snapshot) and again on every TRANSITION. `state` is derived from the wallet DB's synced peak +
  initial-catch-up flag; a `stop` sync event pushes `disconnected`. The client renders "Syncing…
  (peak/target)" and gates trust in balances/spends on `synced`.
- **`event`** (PUSH) — `{ "type":"event", "event": <SyncEvent> }`, where `<SyncEvent>` is the tagged-union
  wire shape of §18.14 (`{"type":"coin_state"}`, `{"type":"stop"}`, …). Every published sync event is
  forwarded to each connected socket (best-effort; a lagging subscriber skips the gap).
- **`tip`** (PUSH) — `{ "type":"tip", "tip": <tip-ledger-entry> }` (§18.23). Pushed when the tipping
  subsystem records a tip. Carried on a DEDICATED bus (NOT the Sage `SyncEvent` union), so it never
  appears on the `GET /events` Sage-parity SSE stream — only on `/ws`.

**Subscription model.** A connected socket is IMPLICITLY subscribed to `sync_status` + `event` pushes for
its lifetime — the client gets one socket, no explicit subscribe call. A transport ping every ~5s with a
pong-timeout closes a half-open socket (as §4.5).

**Authorization (§7.12).** Over `/ws`, wallet READS are open to the local client; every wallet MUTATION
and every `control.*` method REQUIRES the frame's `token` to be the master control token OR a valid
paired token (pairing-admin `control.*` needs the master token). A retired `wallet.*`/`auth.*` name is
refused outright, with or without a token. An
unauthorized request gets an `ok:false` response with an `unauthorized` error — the op never runs and is
never relayed upstream. `pairing.request`/`pairing.poll` are open (the bootstrap, §7.11).

---

## 5. JSON-RPC surface (read plane)

The method catalogue (§5.5), request/response types, tier classification, and error taxonomy (§10)
below are the canonical set defined in the **`dig-rpc-protocol`** crate (§1.4) — the single source of
truth shared with `rpc.dig.net`. This node MUST NOT diverge from it.

### 5.1. Envelope rules

- `POST /` accepts a **single JSON-RPC 2.0 request object**. A non-object body (including a batch
  array) MUST be answered in-band with HTTP 200 and an `INVALID_REQUEST` (`-32600`) error envelope
  — never a transport-level failure.
- All JSON-RPC responses (success and error) are returned with HTTP **200**. The error taxonomy
  lives in the JSON-RPC `error` object (§10), not in HTTP status codes (the sole exception is the
  421 Host rejection, §4.2).
- Error envelopes minted by the shell OR by the node engine MUST carry the numeric JSON-RPC `code`
  plus `data.code` (stable UPPER_SNAKE symbolic name) and `data.origin` (§10). Agents branch on the
  symbolic name, never on message prose. Within the node ENGINE (`dig-node-core`) both fields are
  derived from `dig-rpc-protocol`'s `ErrorCode` at every call site rather than restated, so an
  engine-minted number and its name cannot disagree.
- **The shell (`dig-node-service`) sources every code it shares with the contract crate from
  `dig_rpc_protocol::ErrorCode` rather than restating it**, so a shell-catalogued number and its name
  cannot disagree with the crate either. `-32004` is `RESOURCE_UNAVAILABLE` on both sides and on every
  frame the node emits. The single remaining shell-specific string is `DISPATCH_FAILED` at `-32000`,
  which the shell alone mints and publishes; the crate's generic name for that number is
  `SERVER_ERROR`, and reconciling the two is tracked separately.
- **The ONE exception, stated rather than left silent:** a code this node emits that
  `dig-rpc-protocol` does not declare carries NO `data` object at all. Today that is `-32001`
  alone (the push-authority refusal, §21.9), which `SYSTEM.md` records as reserved-by-occupancy.
  An absent `data.code` is a truthful gap; an invented one would publish a branch key that no
  contract defines and that the owning crate may later assign a different meaning. Declaring
  `-32001` canonically is release-first work in `dig-rpc-protocol`, after which it gains `data`
  with no change to its number and no break for existing readers.
- The response `id` echoes the request `id`, defaulting to `null` when absent.

### 5.2. Dispatch order

For each request, in order:

1. `rpc.discover` → answered by the shell with the OpenRPC document (§6.3) as `result`.
2. `control.*` → the control plane (§7): authorization gate, then `dispatch_control`.
3. Everything else → normalized (§5.3), then dispatched to `dig_node_core::handle_rpc` on a
   spawned task. A panicked/failed dispatch task yields `DISPATCH_FAILED` (`-32000`); the server
   MUST survive it.
4. If the read path returns `-32601` (method not found), the shell relays the **original,
   un-normalized** request to the upstream (§5.4).

### 5.3. Request normalization

Applied ONLY to content/proof methods (`dig.getContent`, `dig.getCapsule`, `dig.getModule`,
`dig.getProof`) and only when the canonical field is absent — an explicit value MUST never be
overwritten:

`dig.getModule` is in that list because it is advertised as an ALIAS of `dig.getCapsule`: an alias
that normalizes differently is not an alias, and would reject `storeId` input its twin accepts.
The capsule-scoped reads added in §5.5.0's family (`dig.getMetadata`, `dig.getPublicManifest`) take
the same `{store_id, root}` shape but are NOT yet normalized — tracked in
DIG-Network/dig_ecosystem#2107, along with the `root`/`"latest"` resolution this section predates.

- `storeId` → `store_id`;
- `resource_key` / `resourceKey` → `retrieval_key`.

A `"latest"` or non-64-hex `root` is passed through untouched: the read path treats it as rootless
and proxies, which is correct for this shell (it performs no chain resolution of "latest").
Requests for all other methods MUST pass through byte-unchanged.

### 5.4. Passthrough relay — opt-in, and never to itself

**There is no default upstream (§3.4).** When the read path answers `-32601` and NO upstream is
configured, the shell MUST return that `-32601` to the caller. That is the truthful answer for a
method the node does not implement, and it is what keeps an unrecognised method — and its params,
which can name stores and carry retrieval keys — from being forwarded to a host the operator never
chose. The shell MUST NOT substitute a well-known host for an absent one.

When an upstream IS configured and has not been proven to loop (§3.4.1), the shell MUST POST the
client's ORIGINAL request verbatim (JSON body) to it and return the upstream's parsed JSON envelope
unmodified. The shell is a transparent proxy for these methods: it MUST NOT rewrite params, results,
or upstream error codes. If the upstream is unreachable or returns non-JSON, the shell mints
`UPSTREAM_ERROR` (`-32010`). The relay client identifies itself with the User-Agent
`dig-node/<version>`.

Passthrough is NOT the node's content-miss path. A read for content this node does not hold is
resolved over the peer network — DHT provider lookup, then redirect or fetch-through per
`DIG_NODE_ON_MISS`. With no upstream configured, a resource no peer serves is reported as `-32004`
(resource not available at this root), NEVER as an upstream/configuration error: the resource's
availability is the caller's concern, this node's upstream configuration is not.

### 5.5. Method catalogue

`meta::methods()` is the single source of truth for the method catalogue; `rpc.discover`,
`/health.methods`, `/openrpc.json`, and `/.well-known/dig-node.json` are all generated from it and
MUST NOT re-declare method names. Each entry carries a `served` class and `requires_auth` flag:

| `served` | Meaning |
|---|---|
| `local` | Resolved by the node library (`handle_rpc`). |
| `passthrough` | Read path returns `-32601`; relayed verbatim to the upstream WHEN one is configured (§5.4), else returned to the caller as `-32601`. |
| `shell` | Answered by this service itself (`rpc.discover`). |
| `control` | The gated control plane (§7); always `requires_auth: true`. |

For the current node library (§2.2) the catalogue is:

- **local**: `dig.getContent`, `dig.getAnchoredRoot`, `dig.getManifest`, `dig.getPublicManifest`,
  `dig.getMetadata`, `dig.getProof`, `dig.getCapsule` / `dig.getModule`, `dig.stage`,
  `dig.getCollection`, `dig.listCollectionItems`, the L7 peer surface (`dig.getNetworkInfo`,
  `dig.getPeers`, `dig.announce`, `dig.getAvailability`, `dig.listInventory`, `dig.fetchRange`),
  all `cache.*` (`cache.getConfig`, `cache.setCapBytes`, `cache.clear`, `cache.listCached`,
  `cache.removeCached`, `cache.fetchAndCache`, `cache.pushCapsule` — §5.5.3), and the chat subsystem
  `chat.send` / `chat.poll` (§5.5.2).
- **passthrough**: `dig.listCapsules` (needs a chain generation walk this node does not perform)
  and `dig.getProofStatus` (polls an execution-proof JOB this node does not run — inventing a
  status would be the fabrication the anti-fabrication rule forbids: an absent attestation is
  reported as absent, never as a passed check). Both are honestly unserved rather than merely
  unwritten; a node with no upstream answers `-32601` for them, which is correct.
- **shell**: `rpc.discover`, `dig.health`, `dig.methods`. A node MUST answer its own liveness and
  its own method list on its own authority — neither may depend on an upstream being configured
  (#1997). `dig.health`'s PUBLIC result is liveness only (`status`, `version`, `methods`); the
  operational body (cache dir, bound addr, upstream, commit) stays on the loopback-only
  `GET /health`, because `dig.health` is anonymously reachable through the rpc.dig.net public read
  tier.
- **control**: the operator `control.*` methods of §7.4, plus the node-owned control methods the
  shell delegates to the node (`control.peerStatus`, `control.peers.connect`, `control.subscribe`,
  `control.unsubscribe`, `control.listSubscriptions`).

Param/result schemas for the `dig.*`/`cache.*` methods are owned by the digstore dig RPC and
published on docs.dig.net (Protocol → the L7 read/RPC pages); this repo's OpenRPC document is a
method + error **discovery** catalogue with intentionally permissive schemas.

Every non-`control.*` method MUST have `requires_auth: false`; every `control.*` method MUST have
`served: "control"` and `requires_auth: true`.

#### 5.5.0. `dig.getContent` — the window envelope (#2071)

A `dig.getContent` result is ONE window of a resource's ciphertext, and a client reassembles the
windows itself. The envelope MUST therefore describe both the WHOLE resource and THIS window:

| field | on | meaning |
|---|---|---|
| `ciphertext` | every window | base64 of this window's ciphertext bytes |
| `total_length` | every window | the FULL resource's ciphertext length in bytes |
| `offset` | every window | this window's start offset within the resource |
| `length` | every window | this window's byte length |
| `complete` | every window | whether this window ends the resource |
| `next_offset` | every window | the next window's offset, or **`null`** on the last one |
| `root` | every window | the generation root the window was served against |
| `inclusion_proof` | every window | base64 whole-resource Merkle inclusion proof |
| `chunk_lens` | prologue (once per stream, PAGED) | per-chunk ciphertext lengths of the WHOLE resource |
| `source` | node profile | `"local"` or `"remote"` — where this node served it from |

This table is normative and MUST agree field-for-field with `ChunkObject` in docs.dig.net's
`static/openrpc.json`, which is the ecosystem-wide publication of the same contract. All of
`ciphertext`, `total_length`, `offset`, `length`, `complete`, `next_offset`, `inclusion_proof` and
`root` are REQUIRED there; a node that omits any of them is non-conforming even when the bytes it
serves are correct.

`total_length` MUST be present on EVERY window, not only the last: a client allocates its
reassembly buffer from it before it has seen the last window. `next_offset` MUST be present on
every window as an explicit `null` when complete, so a client ending its loop on
`next_offset == null` can distinguish "the resource is complete" from "this server omitted the
field". Both requirements are load-bearing rather than cosmetic — omitting them took every
`*.on.dig.net` subdomain dark while this node returned correct ciphertext and a correct,
verifying inclusion proof, and reported no error anywhere (#2071).

`inclusion_proof` MUST ride EVERY window, and MUST always be PRESENT — as the empty string when
the served resource carries no proof, never as an absent key. It describes the whole resource, so a
client that resumes, or begins its stream at a non-zero offset, has no other source for it; sending
it only on window 0 leaves every later window of a multi-window resource unverifiable, which is
#2071's failure mode relocated to large resources rather than fixed. Present-and-empty is a fact a
client can act on; absent is one it must guess at.

The proof verifies the resource, NOT the window: verification requires
`proof.leaf == SHA-256(the whole reassembled ciphertext)`, so a client cannot check a window in
isolation and MUST hold the complete resource before verifying. Every window carries the proof so
that whichever window a client happens to receive first can supply it — not so that windows can be
verified independently.

`chunk_lens` is a PROLOGUE field: it describes how to split the REASSEMBLED resource, so a client
cannot act on it until it holds every window, and a client that begins mid-resource cannot decrypt a
multi-chunk resource and MUST fetch from the start. It is sent once per stream and MUST NOT be
repeated. On the peer length-prefixed frame stream it is **PAGED**: a layout exceeding
`dig_nat::MAX_CHUNK_LENS_PER_FRAME` (2048) entries cannot state itself on one frame, so it is split
into pages of at most 2048 entries each, and every frame carrying a page is stamped with the
`chunk_lens_offset` at which its page begins. When the requested bytes are exhausted before the
layout is fully sent, the remaining pages ride trailing **prologue-only continuation frames** — a
frame with a zero-length data payload that carries byte-`offset = 0` (NOT the ascending byte cursor,
which by then equals the resource length and would trip a reader's `offset >= max_len` establish
guard) and NO `chunk_index` (it begins no chunk, and a stale index would trip the reader's
ascending-index rewind guard). A prologue-only frame does NOT terminate the stream; the stream is
complete only once the bytes are exhausted AND every prologue page has been sent. (The single-frame
JSON-RPC `dig.fetchRange` response is not framing-bound and carries the whole layout on its one
frame.)

**Window size.** A window is at most **3 MiB** of ciphertext. This node currently IGNORES the
`length` request parameter and always serves a full window (or the remainder), where
`openrpc.json` documents `length` as a requested size clamped to the server maximum; a client MUST
therefore size its stride from the `length` it is GIVEN, never from the one it asked for. The
3 MiB figure is presently defined independently in three places — `WINDOW`
(`crates/dig-node-core/src/lib.rs`), `RPC_MAX_CHUNK` (hub.dig.net's retrieval Lambda) and
`RPC_CHUNK` (on.dig.net's resolver service worker) — and a client stride LARGER than the server
window produces gapped buffers. Consolidating it into `dig-constants` is tracked in DIG-Network/dig_ecosystem#2076; until
then any change to it MUST be made in all three.

**One builder, with one honest exception.** The locally-held read and the peer fetch-through MUST
both emit this envelope from the single shared builder (`content_window_envelope`) — a second
implementation of a shared wire shape is what produced #2071. The response-window cache is the
exception: it replays a previously-proxied UPSTREAM `result` verbatim, so a window cached from a
non-conforming upstream is re-served with whatever fields that upstream sent. The cache preserves
provenance rather than rewriting it; conformance there is the upstream's obligation.

Because a replayed window is indistinguishable on the wire from a freshly built one (it is stamped
`source: "local"` like any other local serve), the response-cache key MUST carry an envelope SCHEMA
version, and that version MUST be bumped whenever this envelope's shape changes. Without it an
upgraded node would keep serving windows captured under the OLD shape until they aged out of the
LRU — so "the fix is deployed" would not imply "the fix is what clients receive". Bumping the
version strands every prior entry by construction; no eviction pass or migration is required.

#### 5.5.1. `dig.getManifest` (#176 Phase C)

Resolves the store's normalized **PUBLIC MANIFEST** — the `.dig` format's data-section id 13
(digstore SPEC.md § the `.dig` format), the store's complete public file surface (the LATEST
version per path) as of a given capsule's commit. PUBLIC, unencrypted data; no `retrieval_key`.

- **Params**: `{ store_id, root }` — both 64-hex, a capsule identifier (`storeId:rootHash`),
  matching the shape of the other capsule-scoped read methods (`dig.getAvailability` items,
  `dig.fetchRange`).
- **Result on a hit with a manifest**: `{ schema_version, entries: [ { path, latest_root,
  generation_index, sha256_latest, version_count } ] }`, entries sorted ascending by `path`.
  Byte-identical to `PublicManifest::to_json` (the same renderer the digstore CLI's `manifest
  --json` and the `dig-client-wasm` `readPublicManifest` reader use).
- **Result when the module carries no `PublicManifest` section** (an older `.dig`, or a PRIVATE
  store whose paths must stay opaque): `result: null` — **NEVER an error**. Store-format §5.1: an
  optional section's absence is a normal, backwards-compatible outcome.
- **When this node does not hold the requested capsule at all**: `-32004` (the same
  `RESOURCE_UNAVAILABLE` code `dig.fetchRange` reports on a miss) — distinct
  from the "held but no manifest" case above.
- Malformed `store_id`/`root` (not 64-hex) → `-32602` before any filesystem access.

##### Decoded-manifest memo — a BYTE budget, not an entry count (DoS bound, #2145)

`dig.getManifest`, `dig.getPublicManifest`, and `dig.getMetadata` all decode from the SAME whole-`.dig`
read (the public/metadata data sections share the wasm data section with the content chunk pool, so
the parse cannot seek past them). All three are on the ANONYMOUS public-read allowlist, so that decode
is memoized per `(cache_dir, store, root)` to keep a ~200-byte unauthenticated request from re-reading a
128 MiB capsule per call.

The memo is bounded in **total BYTES**, never in entry COUNT. A manifest entry's size is
publisher-controlled and unbounded (a `PublicManifest` is one row per public path; a
`MetadataManifest`'s `custom`/`links`/`authors`/… are open-ended), so an entry-count cap would let one
hostile capsule pin arbitrary memory. The memo MUST therefore:

- retain only the RENDERED JSON of each section (an exact byte length, never a hand-estimated size of a
  decoded attacker-shaped tree);
- bound the SUM of retained bytes across all entries to a fixed budget (`MANIFEST_MEMO_MAX_BYTES`,
  32 MiB — a hard RAM bound, NOT scaled by publisher input), evicting least-recently-used entries on
  insertion until within budget;
- REFUSE to retain any single entry over a per-entry ceiling (`MANIFEST_ENTRY_MAX_BYTES`, 4 MiB) — an
  oversized capsule is re-decoded per request under a process-wide serialization lock instead of pinned;
- a memo MISS always recomputes and MUST still succeed (never an error);
- `cache.clear` MUST DRAIN the memo (it is a process-lifetime residency with no idle TTL), so an
  operator can reclaim its RAM.

##### `dig.getMetadata` — the response ceiling (DoS bound, #2145)

`dig.getMetadata` renders the WHOLE publisher metadata section into one JSON-RPC response — it cannot be
windowed like `dig.getContent`/`dig.getCapsule`, whose 3 MiB windows seek the module. Because `custom`/
`links` are publisher-controlled, an oversized section is REFUSED with `METADATA_TOO_LARGE` (`-32015`)
when its rendered length exceeds `METADATA_RESPONSE_MAX_BYTES` (3 MiB, the same ceiling as a content
window), rather than rendered + re-serialized (3–4 in-RAM copies) into a ~100 MB response. The refusal is
a bounded error, never the oversized body. A normal (kilobyte) metadata section is served unchanged — the
ceiling only bites the hostile case.

##### `dig.getMetadata` — pre-decode input caps (memory-DoS bound, #2160)

The response ceiling above bounds the RENDERED output, but the danger is the DECODE that precedes it:
decoding the metadata section materializes each `custom` value from JSON TEXT into a `serde_json::Value`
tree, and the flat-numeric shape (`[0,0,…]`) expands ~16× (a 40 KB `custom` → ~640 KB of `Value` nodes).
A hostile `custom` filling a 128 MiB section therefore reaches ~2 GiB of transient `Value` on a ~1.9 GiB
host — BEFORE the rendered-length check can fire. Sizing that decoded output by hand is intractable
(five failed attempts); the node instead caps the INPUT structurally, before decode:

- **Section size** — an ENCODED metadata section over `METADATA_SECTION_MAX_BYTES` (3 MiB, equal to the
  response ceiling) is refused with `METADATA_TOO_LARGE` (`-32015`) without decoding. Rendering does not
  shrink these shapes, so any section whose encoded body clears 3 MiB would fail the response ceiling
  anyway — this only moves the same refusal ahead of the ~16× expansion. A section this size decodes to
  at most ~48 MiB of transient `Value`, and the cold decode is SERIALIZED so at most one runs at once.
- **`custom` shape** — before any `custom` value is parsed, its raw JSON text is streamed (never
  materialized) and refused with `-32015` if the map carries more than `MAX_CUSTOM_ENTRIES` (4 096)
  entries, or any value nests past `MAX_CUSTOM_JSON_DEPTH` (32) or exceeds `MAX_CUSTOM_JSON_ELEMENTS`
  (65 536) structural nodes. These bound the amplifier shapes that fit under the size cap.

Both caps run BEFORE `MetadataManifest::decode`, and the refusal verdict is memoized like any other, so a
repeated hostile request cannot re-drive the decode. A normal (kilobyte) metadata section decodes and
serves BYTE-IDENTICALLY — the caps only bite oversized or hostile-shaped input.

#### 5.5.2. Chat subsystem — `chat.send` / `chat.poll` (epic #793)

The node is the directed-message **TRANSPORT** for dig-chat: an application seals its own opaque
`DIGCHAT1` message body and the node wraps that blob in an e2e-sealed `dig-message` envelope
addressed to the recipient's `0x0010` BLS identity key, then dig-gossip directed-sends it over
opcode 220 (`DIG_MESSAGE`). The node NEVER parses the `DIGCHAT1` body — it is carried verbatim in
`dig_chat_protocol::ChatMessage::envelope` (message type id `0x0000_0200`, dig-message's dig-chat
band).

**Double seal (NC-1, content-blindness).** Two independent seals stack: the inner `DIGCHAT1` seal
the app applies, and the outer `dig-message` seal to the recipient's BLS key. A relay or on-path
peer sees only the outer ciphertext; a peer that terminates the outer seal still faces the inner
one. The node cannot expose chat plaintext even in principle. A conformance test asserts neither
the plaintext body nor the plaintext message id appears in the on-wire sealed bytes.

- **`chat.send`** — seal + directed-send. Params `{ recipient_did (64-hex), recipient_pub (base64,
  the recipient's 48-byte BLS G1 sealing key), peer_id (64-hex, the gossip directed-send target),
  envelope (base64, the opaque `DIGCHAT1` bytes) }`. Result `{ message_id }` (64-hex, a
  node-minted `SHA-256(sender_did ‖ counter ‖ envelope)`). Each send stamps a strictly-monotonic
  per-node anti-replay counter and a 5-minute expiry (dig-message §5.6/§5.6b). Errors: `-32050`
  (no node identity key), `-32602` (missing/malformed param), `-32051` (no peer network), `-32052`
  (seal or directed-send failed). The node seals as the node identity DID
  `SHA-256(node BLS G1 public key)`.
- **`chat.poll`** — drain the inbound inbox. No params. Result `{ messages: [{ sender_did (64-hex,
  the verified envelope sender), message_id (64-hex), envelope (base64, the opaque `DIGCHAT1`
  body) }] }`, in arrival order, leaving the inbox empty. The inbox is bounded (oldest evicted at
  capacity) so a paired peer cannot grow node memory without bound.

**Authorization (F1, #1946).** BOTH `chat.send` and `chat.poll` are **control-token gated** on every
transport (HTTP `POST /` and the `/ws` request plane), exactly like a `control.*` mutation: the caller
MUST present the master control token (§7.3) OR a valid paired controller token (§7a). A loopback
address does not authorize them — any local process can reach the RPC plane — because `chat.send`
wields the node's OWN `0x0010` signing identity to seal + BLS-sign an arbitrary directed message, and
`chat.poll` DRAINS (deletes) the inbound inbox, which an unauthorized process could otherwise use to
steal or delete another app's queued ciphertext. An unauthorized call is rejected with `-32030`
`UNAUTHORIZED` BEFORE any seal/send or inbox drain runs (the fail-closed empty-token rule of §7.2
applies — a blank/absent token is never a credential on either transport).

**Inbound path.** A received opcode-220 frame is opened (`dig-message` unseal → BLS-G2 signature
verify → anti-replay → expiry), routed through the chat `MessageRegistry`, and the decoded
`ChatMessage` is queued into the inbox. A sender the node cannot resolve to a BLS key is rejected,
never queued (fail-closed). This describes the inbound handler (`process_inbound_frame`), which is
implemented and unit-tested; the **live peer-network feed that invokes it is not yet wired** into
`run_peer_network` (see Deferred), so in the shipped build `chat.poll` returns empty until that
loop lands.

**Deferred (epic #793):** the **live inbound feed** — the `run_peer_network` loop that drains
`GossipHandle::inbound_receiver()` into `process_inbound_frame` — is not yet wired (the handler is
implemented + unit-tested but nothing in production calls it, so `chat.poll` is always empty until
this lands; it is gated on the sender-key resolver below). The sealing-key directory
(`resolveSealingKey`) that maps a recipient DID to its attested `0x0010` BLS key + gossip `PeerId`,
and the inbound sender-key resolver, are NOT in this MVP — the app supplies `recipient_pub` +
`peer_id` on `chat.send`, and the inbound resolver is caller-supplied. Group chat, onion routing, and receipt UX are out of scope; the five
chat message types (message, delivery/read receipts, typing, presence) are defined in
`dig-chat-protocol` but only `ChatMessage` surfaces to `chat.poll`.

#### 5.5.3. `cache.pushCapsule` — the publish→seed push (#1476)

The seed leg of the content-replication flywheel: the store owner hands a FRESHLY-COMMITTED `.dig`
capsule straight to their own node so the node becomes a discoverable DHT holder the instant the
content is published, instead of waiting to be asked for it first. It is the reverse of
`dig.getCapsule` (§5.5 served LOCALLY — one bounded window per request): the bytes are PUSHED
in windows the node reassembles, then verified and landed through the ONE shared land site every
other cache path uses (so a seeded capsule is discoverable byte-for-byte identically to a pulled one,
and lands + announces exactly once — SPEC §14.1/§14.3).

**Chunked wire.** A capsule exceeds the ~6 MB inline JSON-RPC ceiling, so it is pushed in ≤3 MiB
base64 windows (mirroring `dig.getCapsule`'s `CAPSULE_WINDOW_BYTES`). Params:
`{ store_id (64-hex), root (64-hex), data (base64, this window's bytes), offset? (u64, default 0),
total_length? (u64, default = this window's decoded length ⇒ single-shot), signature? (192-hex, a
96-byte BLS signature — required only in open mode, below) }`. Pushes are STRICTLY forward: the only
accepted `offset` is exactly the assembled length so far (no gaps, no overlaps); `total_length` is a
commitment fixed on the first window and constant after; and `total_length` may not exceed the
whole-capsule ceiling (`MAX_CAPSULE_BYTES`, 4 GiB). Result mirrors the chunk-ack shape:
`{ offset, complete (bool), next_offset (u64 | null), size_bytes }`, plus `served_root` on completion
and `already_cached: true` for an idempotent re-push. The client repeats with `offset = next_offset`
until `complete: true`.

**Verification, on the completing window (before landing).** (1) INTEGRITY: the reassembled bytes
MUST be a genuine `.dig` module committing exactly the requested `(store_id, root)` — checked with the
same digstore-bound verifier every other land runs. (2) IDEMPOTENCE: a capsule already held is a
no-op that neither re-writes nor re-announces (no double-announce). Only on a fresh, verified land
does the node write `<cache>/modules/<store>/<root>.dig` and announce itself a DHT holder.

**Trust posture — local-only by default (SECURITY-CRITICAL).** `cache.pushCapsule` is a MUTATOR with
a durable holder side effect. It is **absent from the peer allowlist**, so an inbound mTLS peer is
answered `-32601` before dispatch (audit #179), exactly like every `cache.*`/`control.*` method. Over
the loopback HTTP surface it carries the SAME control-token landing gate as `cache.fetchAndCache`
(master control token or a paired controller token — §7): a loopback address alone does not prove the
operator authorized it. The in-process FFI path is trusted-by-locality and ungated.

**Open mode — `DIG_NODE_PUSH_OPEN` (default `false`).** Setting `DIG_NODE_PUSH_OPEN=true` admits
`cache.pushCapsule` to the peer/mTLS surface. Locality no longer implies authority there, so an
OPENED push MUST additionally prove the caller is the store's **§21.6/§21.9 authorized writer** for
the target store: the pushed module commits a publisher public key whose `SHA-256` DERIVES `store_id`
(`store_id = sha256(publisher_pubkey)`, the DIG store-identity derivation), AND the request carries a
BLS signature over `SHA-256(root || store_id)` that verifies under that key. The merkle-integrity
check RECOMPUTES the merkle root from the capsule's own SERVED CONTENT — for each **current-generation**
`KeyTable` entry, `leaf = resource_leaf(concat_output(its ChunkPool ciphertexts))`, the leaves sorted
ASCENDING by `static_key`, folded with `MerkleTree::from_leaves` — and refuses the push unless it
reproduces the committed `CurrentRoot`. The recompute is SCOPED TO THE CURRENT GENERATION: the embedded
`KeyTable` is multi-generation (the producer stores one entry per (generation, resource), each stamped
with THAT generation's root), but the committed `CurrentRoot` is folded over the CURRENT generation only
(`current_generation_leaves(generations.last())`), whose `gen.root()` equals `CurrentRoot`. So the
recompute folds ONLY entries whose `entry.generation == CurrentRoot`; folding every generation's entries
over-counts and would false-reject the genuine current content of any store published then updated even
once (#2246). The recompute is also BOUNDED against a remote pre-auth OOM/CPU-DoS: `chunk_indices` is
attacker-controlled and permits repeated indices (the producer dedups chunks), so the TOTAL referenced
ciphertext bytes across the module is capped at `MAX_STORE_BYTES` and each resource's leaf is hashed by
STREAMING its ciphertexts into an incremental SHA-256 (O(1) memory) rather than materializing their
concatenation — without which a ~1 MB module addressing one chunk N times could reference gigabytes and
abort the allocator (#2246). The recompute resolves each reference through a `ChunkPool` PRE-INDEX built
in ONE linear pass (per-chunk byte ranges), so the whole recompute is O(pool + references), NOT the
Θ(references × pool) it would be if each reference re-walked the pool from offset 0 (the canonical
`read_chunk` is O(global_index)); an attacker could otherwise pin a CPU core for ≈Θ(module²) with a pool
of ZERO-LENGTH chunks + one entry referencing the highest index N times — and because zero-length chunks
add 0 bytes, the byte cap alone never fired. As additional defense-in-depth the CUMULATIVE reference
count across the current generation is capped at `MAX_STORE_BYTES / 4` (a genuine store cannot frame more
chunks than that 4-byte-minimum-framing ceiling permits), bounding scan+hash work even for zero-length
chunks (#2246). The attacker-supplied `MerkleNodes` digests are NEVER trusted for this
decision (retained only as a defense-in-depth cross-check that the served inclusion proofs match the
content): a single-leaf `from_leaves(vec![x]).root() == x` meant a `MerkleNodes = [chain_root]` plus an
empty/garbage `ChunkPool` recomputed to the committed root for free, admitting a contentless
phantom-holder capsule (#2246/#2240). An absent `KeyTable`/`ChunkPool`, a chunk index the pool cannot
satisfy, an undecodable section (including malformed `ChunkPool` framing), a `MerkleNodes`↔content
mismatch, referenced content exceeding `MAX_STORE_BYTES`, or references exceeding `MAX_STORE_BYTES / 4`
fails closed; a legitimately EMPTY store folds to `from_leaves(vec![]).root() == sha256(&[])` and passes. A header naming the chain root is
not proof the bytes hash to it. This
check gives INTEGRITY, never AUTHORITY — without the writer check an opened node would be an
unauthenticated cache-poison + DHT-announce-amplification surface (the #179/#1576 class). A push that
arrives on the peer surface with no signature, a signature under a key that does not derive
`store_id`, or a signature the store key does not verify is rejected (`-32001`) before landing.
`DIG_NODE_PUSH_OPEN` is dig-node-LOCAL (only dig-node reads it; deliberately NOT a `dig-constants`
value).

### 5.6. OpenRPC drift guard (conformance test)

`tests/openrpc_drift_guard.rs` pins the catalogue to reality and MUST be kept passing:

- every `served: "local"` method, dispatched through the real `handle_rpc`, MUST NOT return
  `-32601`;
- every `served: "passthrough"` method MUST return `-32601` from the node (the relay cue).

When a node-library change moves a method between `local` and `passthrough`, the catalogue MUST be
flipped in the same change or this test fails. The test is hermetic (empty params fail validation
before any network I/O; `dig.getContent` and `cache.fetchAndCache`, which would reach the network,
are asserted by classification only).

---

## 6. Discovery surface

### 6.1. `GET /health`

Returns `{ status: "ok", service, version, commit, mode: "local-node", addr, upstream, cache:
{ dir, cap_bytes, used_bytes, shared }, sync: { available }, peer_tier: { attached },
methods: [names…] }`. The fields `status`, `version`,
`mode`, `upstream`, `cache` are the stable probe contract (the v0.2 server's health shape);
additions MUST be additive. `cache.shared` reports whether the effective cache dir is the shared
canonical one (`true`) or a process-private fallback (`false`), from the read path's resolver.

`peer_tier.attached` (#1763) reports whether the P2P content engine is attached RIGHT NOW — the same
state a served response reports as `X-Dig-Peer-Tier` (§4.6). `status: "ok"` means the node is live and
answering; it does NOT imply a usable peer tier, since the HTTP surface opens before the peer network
attaches (§7.8). A client or harness that needs the peer tier MUST poll `peer_tier.attached` until it
is `true` rather than waiting a fixed interval.

### 6.2. `GET /version`

Returns `{ service, version, commit, protocol }` (§2; `version` is the one canonical version).

### 6.3. `GET /openrpc.json` and `rpc.discover`

Both return the same OpenRPC (spec version `1.2.6`) document generated from the method catalogue
and error enum. Each method object carries the machine-readable `x-requires-auth` extension; the
`info` object carries `x-control-auth` describing the control-token scheme (§7.3). Every method's
`errors` array is the full catalogue of §10.

### 6.4. `GET /.well-known/dig-node.json`

The canonical first-fetch discovery document: service identity + versions + protocol, the bound
`addr`, `upstream`, the live cache block (dir, cap/used bytes, shared), the full method catalogue
(name/served/summary/requires_auth), the full error catalogue, and pointers to `/health`,
`/version`, `/openrpc.json`, and the `rpc.discover` method. Its `endpoints` map also carries
`ws_status: "/ws/status"` (§4.5).

### 6.5. `GET /ws/status`

The WebSocket status/liveness channel — see §4.5 for the full message contract (this is the
discovery-surface cross-reference; §4.5 is normative).

---

## 7. Control plane (`control.*`)

This section is the **canonical node-control interface** — the ONE contract every node
controller speaks (the DIG Chrome extension's node UI, the DIG Browser "My Node" surface, the CLI,
any local tool). It is the cross-repo source of truth mirrored in the superproject `SYSTEM.md`
("dig-node control interface"); a consumer's node-control UI conforms to the method names, params,
result shapes, health/status schema, error codes, token model, and served port defined here — never
a parallel interface. A change to any of them is a coordinated cross-repo change (§4.1 in the
ecosystem contract) updating this SPEC, `SYSTEM.md`, and every consumer in one unit.

### 7.1. Role split

The read methods (`dig.*`, `cache.*`, `rpc.discover`) are open to any local consumer. The
`control.*` namespace MANAGES the node (pins, cache, sync, config, status) and is gated so a web
page a user merely visits — which can reach loopback but cannot read local files — cannot drive
the node.

The read methods (`dig.*`, `cache.*`, `rpc.discover`) are open to any local consumer. The
`control.*` namespace MANAGES the node (pins, cache, sync, config, status) and is gated so a web
page a user merely visits — which can reach loopback but cannot read local files — cannot drive
the node.

### 7.2. Authorization model — loopback + local capability token

Two layers, both REQUIRED:

1. **Loopback-only**: the whole server binds loopback (§4.1), so nothing off-machine reaches any
   method.
2. **Local token**: a `control.*` call MUST present a valid control credential — the master control
   token (§7.3) OR, for a non-administrative method, a paired controller token (§7.11); a missing or
   mismatched credential is answered `UNAUTHORIZED` (`-32030`, §10). Token comparison MUST be
   constant-time (`ct_eq`) so verification cannot be probed via a timing oracle.

Exactly the `control.` method prefix is gated (`is_control_method`); unknown `control.*` methods
still pass the auth gate first, then yield `METHOD_NOT_FOUND`. The pairing-administration methods
(`control.pairing.list`/`approve`/`revoke`, §7.11) require the MASTER token specifically — a paired
token is NOT accepted for them. The exceptions are the wallet CHAIN READS — `control.wallet.balance`, `control.wallet.coins`,
`control.wallet.coinById`, `control.wallet.coinSpend`, `control.wallet.coinsByParent`,
`control.wallet.arrivals` and `control.wallet.peak`
(`is_open_control_read`): each is a READ-ONLY
read of PUBLIC chain state with no custody, so each is served WITHOUT a token. The membership rule is
WHO NAMES THE SUBJECT: an open read's subject arrives in the request as a public address or coin id,
so the answer discloses no node-to-address association. They still route through `dispatch_control` (so they
stay in the control catalog and get their CLI verbs) but the server skips the token requirement.
`control.wallet.broadcast` is NOT among them: it puts bytes on the network, so it is token-gated like
every other mutation, and an `UNAUTHORIZED` from it means exactly that (remedy: the token) — where the
same code on an open read can only come from a node too old to serve it (remedy: an upgrade). No
mutation or custody method is ever open.

### 7.3. The control token

- **File: `<state_dir>/control-token`** (§7.3a), where `<state_dir>` is the machine-wide, identity-
  INDEPENDENT daemon state dir — NOT the per-user config dir. This is REQUIRED (#501): on a real
  install the daemon runs as a service under a different OS account (Windows LocalSystem, a root
  daemon) than the operator's interactive CLI. A per-user path resolves DIFFERENTLY for the two
  identities, so the CLI would never see the token the service wrote (and would mint a phantom the
  daemon never trusts). Resolving a machine-wide dir independently of the running user makes the
  daemon and the CLI read the SAME token.
- Value: 32 bytes drawn from the operating-system CSPRNG rendered as 64 lowercase hex characters.
  Generated at first run; subsequent runs (and other same-host processes/users) read the same
  value. The token MUST never be committed or logged.
- Presentation, either of (header preferred): the `X-Dig-Control-Token` request header, or the
  `params._control_token` field. Blank presentations are treated as absent.
- **The daemon MAY create the token (write); an operator CLI MUST NOT mint one.** The CLI
  (`dig-node pair` / any control tool) reads the token READ-ONLY; if it is missing or unreadable it
  MUST fail with a precise remedy (§7.3a) rather than write a fresh token the daemon does not trust.
- **The operator control client MUST connect DIRECT to loopback, ignoring proxy environment.** The
  HTTP client that carries the master control token to the node's loopback address MUST be pinned to
  a direct connection (`no_proxy`), so an `HTTP_PROXY`/`HTTPS_PROXY` in the operator's environment
  can NEVER route the token-bearing `control.*` POST through an interposed proxy. (The default HTTP
  proxy behaviour has no automatic loopback bypass.)
- **Trust a pre-existing token file ONLY when it is owned by a TRUSTED principal (owner
  verification).** Before the daemon loads and trusts the bytes of an EXISTING `control-token`, it
  MUST verify the file's OWNER; a foreign-owned token is DELETED and REGENERATED, never returned.
  This closes the residual where an unprivileged local user plants a KNOWN token in the machine-wide
  state dir (a `%PROGRAMDATA%` squat, or the narrow window during a service harden) so the daemon
  (LocalSystem) reads + trusts it and the attacker learns the control token → full local control
  (local privilege escalation). Trusted owners: **Windows** — `S-1-5-18` (SYSTEM) or `S-1-5-32-544`
  (Administrators) always; a NON-service (dev/operator) run ALSO trusts the CURRENT process user's
  own SID (so a dev token in the legacy per-user dir keeps working), and a SERVICE run requires
  SYSTEM/Administrators. **Unix** — owner uid `0` (root) always, else the CURRENT effective uid AND
  mode `0600` (owner-only); a group/other-readable or foreign-uid token is untrusted. This is layered
  BENEATH the §7.3a state-dir hardening (which already purges a squatter-owned dir on a service run)
  as defense-in-depth: it also guards the non-hardened dev path and any harden gap.
- If the token cannot be persisted (unwritable state dir) OR cannot be minted (the OS CSPRNG is
  unavailable), the daemon MUST fall back to an in-memory token that no controller can read — the
  control plane fails **closed**; the read plane is unaffected. It MUST NEVER emit a guessable
  token in place of a CSPRNG-drawn one.
- **The authorization gate MUST NEVER accept an empty or absent token, on ANY transport.** A blank
  presentation is treated as absent (HTTP header/`params._control_token` AND the WS frame `token`
  field alike), and a node whose configured token is the empty fail-closed sentinel authorizes
  NOTHING — the empty string is never a valid credential (a constant-time comparison of two empty
  strings would otherwise match). This holds identically for the master control token and the paired
  controller tokens; a node with no usable token gates every `control.*`/custody call closed.
- Randomness source: the operating-system CSPRNG on EVERY platform (`getrandom` — `getrandom(2)`/
  `/dev/urandom` on Unix, `BCryptGenRandom` on Windows). There is NO software (non-CSPRNG) fallback:
  when the OS CSPRNG is unavailable the daemon fails closed (above) rather than derive a token from
  time/PID/ASLR entropy. The same CSPRNG source mints the pairing ids/tokens (§7.11) and, layered on
  loopback bind + same-host-readable-file possession, is the token's secrecy guarantee — not an
  attacker's inability to estimate mint time/PID/ASLR.

### 7.3a. The daemon state dir — location, ACL, threat model (#501)

The state dir holds ONLY the control/auth state — the control token (§7.3) and the paired-token
store (`paired-tokens.json`, §7.11). The bulk per-user `.dig` cache and `config.json` (§3.5–3.6) do
NOT move; they stay per-user (shared with the browser/digstore, #96).

**Resolution order** (the daemon and every operator CLI MUST resolve this identically, so it MUST
NOT depend on `$HOME`/`%LOCALAPPDATA%`/the running user):

1. `DIG_NODE_STATE_DIR` (env override) — wins outright (tests + custom deploys).
2. The first machine-wide candidate that already EXISTS — Windows `%PROGRAMDATA%\DigNode`
   (`C:\ProgramData\DigNode`); Linux `/var/lib/dig-node` then `/etc/dig-node`; macOS
   `/Library/Application Support/DigNode`.
3. Only for a SERVICE run (self-identified via `DIG_NODE_RUN_CONTEXT=service`): the first
   machine-wide candidate it can create. A bare CLI MUST NOT create a machine-wide dir.
4. Else the LEGACY per-user dir (the parent of `config.json`) — the back-compat fallback that keeps
   a non-service `dig-node run` as a normal user working exactly as before (additive).

**Service data dirs — identity + cache MUST NOT live under `$HOME`.** On a SERVICE run the node MUST
resolve its persistent identity seed and its content cache UNDER the resolved state dir
(`<state_dir>/identity`, `<state_dir>/cache`) rather than under the invoking user's home, and MUST do
so before the identity is first loaded.

Both otherwise default to a home-relative path (`dirs::config_dir()/dig` for the seed, `$HOME/DigNode/
cache` for the cache), which a system service cannot use: the packaged Linux unit runs with
`ProtectHome=true`, so `$HOME` is unreadable, seed creation fails with `EROFS`, the node starts with
NO identity, and the peer network refuses to come up — a stock package install never joins the
network. The same reasoning binds the macOS launchd daemon and the Windows service, which is why this
is a property of a SERVICE RUN and not of one packaging target.

An `DIG_IDENTITY_DIR` / `DIG_NODE_CACHE` value the operator set explicitly MUST be preserved; a CLI
run MUST be left untouched, keeping the user's identity shared with their other DIG tools.

**Creation + ACL — the HARDENING CONTRACT.** The state dir holds the control token that grants FULL
local control, so its ACL MUST NOT be world/all-users-readable. On Windows this is the HARD case:
`%PROGRAMDATA%` grants `BUILTIN\Users` "create subfolder", so ANY low-priv user can pre-create
`C:\ProgramData\DigNode`, become its CREATOR OWNER, and keep `WRITE_DAC` forever — a naive
`icacls /inheritance:r /grant:r` (which never resets OWNER nor purges foreign explicit ACEs) leaves
that squatter able to rewrite the DACL and read the token → local privilege escalation. A
pre-existing machine dir MUST therefore NOT be trusted blindly.

On a SERVICE run (self-identified via `DIG_NODE_RUN_CONTEXT=service`), BEFORE the daemon writes or
reads the control token, the resolved MACHINE state dir MUST be HARDENED and READBACK-VERIFIED:

1. Resolve the interactive read-grant principal as a real SID from the CURRENT PROCESS TOKEN
   (`whoami /user`), NEVER the spoofable `%USERNAME%`/`%USERDOMAIN%` env. REJECT it if it is a
   well-known group/broad SID (`S-1-1-0` Everyone, `S-1-5-11` Authenticated Users, `S-1-5-7`
   Anonymous, `S-1-5-32-545` Users) or SYSTEM (`S-1-5-18`). A LocalSystem service thus resolves NO
   interactive grant; it instead PRESERVES an installer-set interactive read grant if one is
   discoverable on a TRUSTED (SYSTEM/Administrators-owned) pre-existing dir.
2. Create the dir if absent — but NEVER early-return when it already exists (a squatter may have
   pre-created it); always run steps 3-6.
3. Take ownership so the squatter loses `WRITE_DAC`: `icacls D /setowner *S-1-5-18 /T` (owner ⇒
   SYSTEM). A pre-existing dir with an UNTRUSTED owner is PURGED (`remove_dir_all`) and recreated.
4. Purge ALL foreign explicit ACEs: `icacls D /reset /T`.
5. Lock the DACL: `icacls D /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F` and,
   only when a valid interactive read grant survived step 1, append `<user_sid>:(OI)(CI)R` (READ only
   for the interactive user, never full). Principals are always addressed by SID literal, never the
   localized name.
6. READBACK-VERIFY as the acceptance gate, reading the owner SID + DACL ACEs directly through the
   Win32 security API (`GetNamedSecurityInfoW` → owner + DACL, `GetAce`, `ConvertSidToStringSidW`),
   SID-based and launching NO process. (It MUST NOT shell out to a PowerShell `Get-Acl`: on a host
   that cannot autoload `Microsoft.PowerShell.Security` that spawn throws, which used to be
   misread as a hardening failure and destroy a correctly-hardened dir.) The gate asserts: NO
   Everyone/Users/Authenticated-Users/Anonymous ACE; owner is SYSTEM (or Administrators); SYSTEM +
   Administrators present with full; the interactive read grant present iff one was applied; NO
   principal beyond those; and inheritance disabled. A readable-but-violating DACL FAILS.
7. FAIL CLOSED on a genuine failure: if step 3, 4, or 5 (the SET path) fails, OR step 6 reads a
   DACL that VIOLATES the gate, hardening returns an error, the dir is best-effort DELETED, and the
   daemon MUST NOT write the token there — it falls back to an ephemeral, unshared dir + a random
   in-memory token so the control plane is UNAUTHORIZABLE (never served from an attacker-controlled
   dir). The read plane is unaffected. But when step 6 cannot READ the DACL AT ALL (a transient
   condition), hardening treats the applied lockdown (the step 3-5 SET commands that already
   succeeded) as authoritative and PRESERVES the dir — the defense-in-depth readback never gates
   the applied lockdown, so a correctly-hardened dir is never destroyed merely because it could not
   be read back, and the service converges to a hardened dir with a minted control token.

`dig-node install` (run elevated by the interactive user) applies the SAME hardening as the
installing user, setting owner = SYSTEM and granting THAT user READ, so the LocalSystem service's
startup harden later sees a TRUSTED dir and PRESERVES the grant. Idempotency: running the harden
twice on a legit dir yields the same final ACL. On Unix the dir is `0700` and the token file `0600`,
owned by the daemon identity (root on a real install under root-owned `/var/lib`, which is not
squattable); the installer additionally best-effort `setfacl`s READ for the `SUDO_USER`.

The CLI (non-service) NEVER hardens (it is not elevated) — it only READS an existing machine dir,
else falls back to the LEGACY per-user dir. A non-service dev run on the legacy per-user dir does NOT
invoke the machine-dir hardening (that dir is already user-scoped).

**Threat model.** The control token grants full local control of the node (mint controller tokens,
change pins, drive wallet-adjacent control). A machine-wide file readable by every local user, or one
sitting in a squatter-controlled dir, would be a local privilege-escalation vector — any user could
seize control of a node running as another identity. The invariant that MUST hold either way is: NO
Users/Everyone/Authenticated-Users ACE and owner = SYSTEM. The ACL is defense-in-depth layered on the
loopback bind + token-possession model, BUT because a loose ACL is itself a priv-esc, the SERVICE-run
harden is FAIL-CLOSED (unlike the best-effort dev/self-create path, where an `icacls`-unavailable
tighten failure does not hard-fail startup).

**Degraded case + remedy.** When the daemon bootstraps the dir itself as SYSTEM/root (the installer
did not pre-create it), the interactive user is not a trustee and cannot read the token. The
`UNAUTHORIZED` (`-32030`) error and the operator CLI MUST then print the PRECISE remedy — the exact
token path, and that it needs elevation (Administrator / `sudo`) or the install-user read ACL —
rather than a generic hint. The CLI distinguishes token-present-but-unreadable (the service-vs-user
split → "elevate / grant read") from token-absent ("start the node so it mints one"). This
distinction MUST be made by the READ error KIND, NOT by `path.exists()`: under a locked-down DACL the
invoking user cannot even STAT the file, so `path.exists()` reports `false` and would misclassify an
ACL denial as "not found" (#772). A `PermissionDenied` read ⇒ present-but-unreadable; any other read
error ⇒ absent. The token-absent remedy MUST also name the STALE-service recovery: a service left
over from an older build (installed before the machine-wide state dir) never mints the token at this
path, so reinstalling the current binary (`dig-node uninstall`, then an elevated `dig-node install`,
then `dig-node start`) is the fix for a "service running yet token missing" report on an in-place
upgrade.

### 7.4. Control methods

All results/errors use the standard envelopes of §5.1. `storeId` and `rootHash` are canonical
lowercase 64-hex; a capsule reference is `storeId:rootHash`. Malformed refs yield
`INVALID_PARAMS`; runtime failures yield `CONTROL_ERROR`; capability absences yield
`NOT_SUPPORTED`.

| Method | Params | Result (essentials) |
|---|---|---|
| `control.status` | — | `running`, `service`, `version`, `commit`, `protocol`, `uptime_secs`, `addr`, `upstream`, `cache`, `hosted_store_count`, `cached_capsule_count`, `pinned_store_count`, `sync.available`, `logging` (`initialized`, `dir`, `file_logging`, `file_error` — a START-UP verdict; see §20.1) |
| `control.config.get` | — | `addr`, `port`, `upstream`, `upstream_override`, `cache_dir`, `cache_shared`, `config_path`, `sync_available` |
| `control.config.setUpstream` | `upstream` (URL string; blank clears) | `upstream` (normalized), `requires_restart: true` — persisted, effective on next start (§3.4) |
| `control.log.setLevel` | `filter` (an `EnvFilter` directive, e.g. `debug` or `info,dig_node_core=debug`) | `filter` (echoed) — live-applied via the `dig-logging` reload handle, effective immediately, NOT persisted (§11); `INVALID_PARAMS` on a missing/malformed directive, `CONTROL_ERROR` when logging is not installed in the process |
| `control.cache.get` | — | `cap_bytes`, `used_bytes`, `capsule_bytes`, `response_bytes`, `dir`, `shared` |
| `control.profile.putBody` | `store_id`, `root` (64-hex), `body_b64` (standard padded base64 of the DPB bytes) | `stored: true`, `store_id`, `root`, `body_bytes`, `announced_to_peers`, `unreachable_peers`. `announced_to_peers` is a TRUE delivery count — peers the 223 announce was actually sent to, excluding lazy and NAT-bound peers that are connected but cannot be pushed to — so `0` does NOT mean failure and MUST NOT be treated as one: the body is persisted either way and the periodic re-announce reaches whoever connects later. `unreachable_peers` reports that connected-but-unreachable remainder, so a caller can distinguish "no peers exist" from "peers exist and none could be reached". The node MUST independently resolve the root on chain and refuse unless the chain confirms exactly that root AND the bytes hash to it (§22.3). A refusal is an ERROR, never an `Ok` carrying `stored: false`. A decoded body above `MAX_BODY_BYTES` (4 MiB) is `INVALID_PARAMS` before anything is persisted. |
| `control.profile.getBody` | `store_id`, `root` (64-hex) | `store_id`, `root` (always the root ASKED for — never a substituted newer one), `body_b64` (`null` ⇔ consulted and holds nothing), `body_bytes`, `standing`. A read that FAILED is `CONTROL_ERROR`, never a `null` body. `standing` is `{state, chain_root, held_roots, detail}` and carries §22.5c's reconciliation: `state` is one of `current` / `superseded` / `nothing_held` / `no_generation` / `chain_unreadable` / `held_unreadable`, and it is what distinguishes an un-published store from an empty one — `body_b64: null` alone is the same answer for at least four different situations. `chain_root` is `null` (NEVER an all-zero root, which the body format rejects outright) whenever the chain named none or could not be read. `held_roots` is `null` when the local store could not be enumerated — distinct from `[]`, which means consulted-and-holds-nothing. A node MUST NOT report an unreadable local store as an empty one, and when the local read fails the node MUST report `state: "held_unreadable"` WITHOUT consulting the chain, because a chain read must never be able to mask a broken disk, the one condition whose remedy is on that machine. The chain read is ADDITIVE: `body_b64` keeps its exact meaning as the disk read at the REQUESTED root, a failed disk read is still `CONTROL_ERROR`, and a chain read that RETURNS an error degrades to `state: "chain_unreadable"` rather than failing the call — a node whose chain access is down MUST still be able to answer what it holds. Named limitation: a chain source that is UNRESPONSIVE rather than failing returns no error to degrade on, so it blocks this call for as long as it blocks — exactly as it already does for `control.profile.putBody`, which resolves the same root through the same resolver as its FIRST action. Bounding that read is one change across both methods, not a bound on this one alone. |
| `control.cache.setCap` | `cap_bytes` (number) | `cap_bytes` (floored at 64 MiB) |
| `control.cache.clear` | — | `cleared: true` |
| `control.hostedStores.list` | — | `stores[]`: `store_id`, `pinned`, `capsule_count`, `total_bytes`, `capsules[]` (capsule, root, size_bytes, last_used_unix_ms) — cached stores ∪ pinned stores |
| `control.hostedStores.pin` | `store` = `storeId[:rootHash]` | `store_id`, `root`, `pinned: true`, `fetch` = `{status: cached\|failed\|skipped, …}` (pre-fetch attempted only with a concrete root AND sync available; a skipped fetch reports `reason`) |
| `control.hostedStores.unpin` | `store` = `storeId[:rootHash]` | `store_id`, `unpinned` (whether a pin was removed), `evicted_capsules` — MUST evict every cached capsule of the store |
| `control.hostedStores.status` | `store` = `storeId[:rootHash]` | `store_id`, `pinned`, `capsule_count`, `total_bytes`, `capsules[]` |
| `control.capsule.fetch` | `store` (64-hex), `root` (64-hex) — BOTH REQUIRED and both canonical; there is no root-less form, because a capsule pull names one concrete generation and choosing one is the chain’s decision (`control.sync.trigger`), not this verb’s | `store`, `root`, `status` ∈ {`"started"`, `"already_cached"`, `"unavailable"`} | This is an ACKNOWLEDGEMENT, not a completion report: a whole-`.dig` pull crosses the network and takes arbitrarily long, so the call MUST return as soon as the pull is launched and MUST NOT block on the transfer. `"started"` therefore means STARTED and MUST NOT be answered for a pull that was not launched; completion is observed through the cache (`control.hostedStores.status`). `"already_cached"` means the capsule was on disk and no pull was started — read from the filesystem, the same evidence the serve path uses, never from an index that could disagree with it. `"unavailable"` means nothing could be started because this build has no capsule warmer (the FFI/base path has no P2P engine). `INVALID_PARAMS` on a missing or non-64-hex `store`/`root`. Authorized like every other write on this plane; it is NOT an open read, because a pull spends this node’s bandwidth on the caller’s choice of content. |
| `control.sync.status` | — | `available` (always `true` — the chunked capsule download needs no identity), `method: "chunked-capsule-download-with-section-21-clone-fallback"`, `identity_loaded`, `pinned_total`, `pinned_synced`, `whole_store_trigger_supported` (`true` — a store id alone is enough) |
| `control.sync.trigger` | `store` = `storeId[:rootHash]`, or `store_id` [+ `root`] — the root is OPTIONAL; without one the node resolves the store's CHAIN-ANCHORED tip and syncs that generation | `status: "synced"`, `root`, `size_bytes`, `served_root` |
| `control.wallet.balance` | `address` (bech32m string), `asset` (`"xch"` \| `"dig"` \| `{"cat":"<64-hex asset id>"}`, default `"xch"`) | `balance` (confirmed, spendable — JSON NUMBER, u64 base units), `pending` (unspent + unconfirmed — JSON NUMBER, u64 base units), `source` (`"db"` \| `"fallback"` — which tier produced the figure, §18.7b), `synced` (bool), `peak_height` (`u32` or `null`). Matches `dig-node-control-interface` 0.3.0's `WalletBalanceResult { balance: u64, pending: u64, .. }` and dig-app's `BalanceResponse { balance: u64 }` — a Rust-to-Rust numeric contract, never a decimal string. The wallet backend tracks the base-unit total as `u128` (headroom for summed intermediate math); the wire boundary saturating-casts to `u64` (a single address's balance can never exceed `u64::MAX` mojos, ~18.4M XCH). READ-ONLY chain read of a PUBLIC address (no seed/signing key). Reuses the B.6 sync-state routing: the local DB when the address is the wallet's own and the DB is synced, else the coinset fallback. Per §18.7b, `source`/`synced`/`peak_height` describe the TIER that answered: a `"db"` answer reports the node's own peak and reports `synced: true` only while the replica is FOLLOWING the chain, so a behind-but-once-synced replica answers `synced: false` WITH its real `peak_height` rather than presenting a stale figure as current; a tier with NO observable peer height also answers `synced: false`, because nothing corroborated the figure, and so does a replica with NO peak of its OWN — `synced: true` beside `peak_height: null` would claim a reading is current while refusing to say what it is a reading of (§18.7b); a `"fallback"` answer reports `synced: false` and `peak_height: null`. This is an OPEN read (`is_open_control_read`, no token); the cheap local-DB fast path is unbounded, but the EXPENSIVE coinset-fallback leg is subject to a GLOBAL token-bucket rate bound (defense-in-depth against an open-read amplification/oracle sweep — #1957): a burst of arbitrary-address fallback reads beyond the bound is refused with `WALLET_RATE_LIMITED` (§10), while any single honest read (DB fast path or one fallback) always succeeds. A CAT scopes by the asset id the REQUEST named -- any CAT, not only `$DIG` -- and BOTH tiers MUST scope to that id. `"dig"` is the canonical id `digstore_chain::dig::DIG_ASSET_ID` spelled as a token, and `{"cat":"<that id>"}` MUST mean the same asset. Every scoping hash a tier derives MUST be derived FROM the requested id: a filter keyed to a fixed asset answers every other CAT an EMPTY list, which is indistinguishable from holding none of it -- a silent wrong answer with nothing to observe. An `asset` that is PRESENT and does not parse is `INVALID_PARAMS`; it MUST NOT default to `"xch"`, because a mistyped asset id would then read as a balance for the wrong token. An OMITTED `asset` is the documented `"xch"` default. A hint is not an asset: the fallback tier finds CAT coins with `get_coin_records_by_hints`, which takes no asset id and answers with EVERY coin hinted to the address -- any CAT of any TAIL, and any plain XCH coin whose spend carried a hint memo -- so a `"fallback"` answer MUST keep only the coins sitting at that asset's CAT puzzle hash (`digstore_chain::cat::cat_puzzle_hash(owner_p2_hash, asset_id)`, the canonical curry), the exact equivalent of the DB tier's `hint IN (...) AND asset_id = ?`. Summing the raw hint answer reports a holding the address does not have, at the asked-for asset's scale rather than each coin's own: one hinted XCH coin of 10^8 mojos (`0.0001 XCH`) totals as `100000` at `$DIG`'s 3 decimals. Over-filtering is the same lie mirrored -- a real `$DIG` holder answered zero -- so the filter MUST key on that puzzle hash and nothing heuristic. A synced empty address is a SUCCESS `{balance:0, synced:true}`, never an error (and `synced` there means MEASURED-current, never merely eligible); the read-failure shapes are DISTINCT errors `WALLET_NO_CHAIN_SOURCE`/`WALLET_NOT_SYNCED`/`WALLET_READ_FAILED`/`WALLET_RATE_LIMITED` (§10), never a fabricated `0`. `INVALID_PARAMS` on a missing/malformed `address` or a bad `asset`.  Additionally `network_peak_height` (`u32` or `null`) — the peak this node's own held Chia peers have ANNOUNCED — and `stale_by` (`u32` or `null`) — how many blocks behind that peak this figure is. `stale_by` MUST be `null` unless BOTH the answer's `peak_height` and `network_peak_height` are known: a zero is a positive claim that the figure is level with the network, and absence is the opposite claim, so a consumer MUST NOT render them alike. It MUST saturate at zero rather than underflow when the replica is momentarily ahead. Both fields are ADDITIVE (§5.1). They exist because `balance 0, synced false, peak_height null` — the answer a replica ~8,380 blocks behind its peers actually gave — is indistinguishable from an empty wallet, and a consumer had nothing with which to tell them apart. |
| `control.wallet.coins` | `address` (bech32m string), `asset` (`"xch"` \| `"dig"` \| `{"cat":"<64-hex asset id>"}`, default `"xch"`), `after_coin_id` (OPTIONAL, 64 lowercase-hex, an `0x` prefix TOLERATED and normalized away), `limit` (OPTIONAL, `1..=1000`, default `100`) | `coins` (array of `{coin_id, asset, amount, parent_coin_info, puzzle_hash, created_height, spent_height}`; all hashes lowercase 64-hex unprefixed, `amount` a JSON NUMBER in base units), `complete` (bool), `cursor` (string \| `null`), `source`, `synced`, `peak_height` — the tier fields carrying exactly their `control.wallet.balance` meanings (§18.7b). ONE PAGE of the UNSPENT coins at the address for the asset, i.e. the read a caller building a spend needs; a balance is this read reduced to a sum, which is why the two take identical params. It scopes to the asset by the SAME tier-agnostic rule, for the sharper reason: a coin list is spend INPUTS, so a hinted XCH or foreign-CAT coin served as a `$DIG` coin is a spend built on inputs of the wrong asset. Coins seen only in the mempool are INCLUDED with `created_height: null`, so the caller decides what is spendable for its purpose rather than the node hiding one. `coins: []` MUST mean a chain WAS consulted and the address holds nothing; every way of failing to consult one is a DISTINCT error (`WALLET_NO_CHAIN_SOURCE`/`WALLET_NOT_SYNCED`/`WALLET_READ_FAILED`/`WALLET_RATE_LIMITED`, §10), NEVER an empty list — an empty list would tell a holder of funds that they hold none, and a spend built on it refuses with an untrue shortfall. The read is PAGED, because an address's unspent-coin count is unbounded and every spend's change coin adds one — the same exposure `control.wallet.coinsByParent` carries, on a control plane with no request rate limiting. A node MUST return coins ASCENDING by `coin_id`, MUST keep that order stable across the pages of one walk, and MUST NOT page by OFFSET: an address's unspent set SHRINKS as coins are spent, so under an offset every row after a departed coin moves one position earlier and the next page begins one row late — a coin the caller never sees, on the read whose purpose is coin selection. A node MUST derive `complete` from whether rows remain BEYOND the page, never from the page LENGTH: a coin count that is an exact multiple of the page size makes the final full page indistinguishable from a truncated one, and a caller stopping there builds a spend from half an address's coins and refuses with an untrue shortfall. The scope, asset, unspent predicate and page bound MUST be applied at the SAME level: paginating a broader read and filtering afterwards cuts the page before the filter, so pages arrive short and `complete` is computed from a count that no longer describes what remains. `cursor` is the `coin_id` of the LAST record actually returned, or `null` for an empty page, and is what a caller passes back as `after_coin_id`. An out-of-range `limit` is REFUSED as `INVALID_PARAMS`, never clamped — a silently shrunk page hands back a cursor for a position the caller did not ask about. Both page params are OPTIONAL and a request naming neither is byte-identical to the pre-paging request. OPEN read, same global fallback rate bound as the balance. `INVALID_PARAMS` on a missing/malformed `address`, a bad `asset`, a malformed `after_coin_id`, or a `limit` outside `1..=1000`. Additionally `network_peak_height` (`u32` or `null`) and `stale_by` (`u32` or `null`), carrying EXACTLY their `control.wallet.balance` meanings (this section) and bound by the SAME null-versus-zero rule: `stale_by: 0` is a POSITIVE claim that this answer is level with the network, `null` is the OPPOSITE claim that nothing bounds it at all, and a consumer MUST NOT render the two alike. `stale_by` MUST be `null` unless BOTH this answer's `peak_height` and `network_peak_height` are known, and MUST saturate at zero rather than underflow. Both fields are ADDITIVE (§5.1). `complete` scopes the PAGE and never the chain: it states that this node handed over every record IT found, while `stale_by` states how much of the chain that was. A consumer MUST NOT present `complete: true` as an unqualified claim that nothing was left out while `stale_by` is `null` — the node has just said it cannot bound its own answer's height, so the two must be read together. |
| `control.wallet.coinById` | `coin_id` (64 lowercase-hex, an optional `0x` prefix TOLERATED and normalized away) | `coin` (`{coin_id, asset, amount, parent_coin_info, puzzle_hash, created_height, spent_height}` or `null`), `source`, `synced`, `peak_height` — the tier fields carrying exactly their `control.wallet.balance` meanings (§18.7b); the tier fields MUST describe WHAT ANSWERED THIS READ. Where the local replica HOLDS the named coin and is authoritative for the set it follows (the same `control.wallet.balance` eligibility test, §18.7b), the node MUST answer from the replica: `source: "db"`, `peak_height` the replica's own peak, and `synced` MEASURED against the peers' announced peak rather than assumed — a replica that completed a catch-up and then fell behind still serves the coin, with its real peak, labelled stale. A replica MISS MUST fall through to the chain tier and be reported as such (`source: "fallback"`, `synced: false`, `peak_height: null`); it MUST NEVER be served as an absence, because the replica is populated only from this node's own subscriptions, so a miss means "this node does not watch that coin", which is NOT absence. A node MUST NOT report `source: "fallback"`, `synced: false` for a coin it holds: a warrant no read can ever carry turns every consumer-side freshness guard into an unconditional refusal, which ends a mint watch in "the chain could not be reached" on a healthy node. ONE coin by its own id, SPENT OR UNSPENT — the read a caller polling a spend needs and `control.wallet.coins` structurally cannot give: a created DID coin sits at nobody's wallet address, and a spent funding coin is gone from every unspent list. `asset` in the record is ALWAYS `null`: a coin id alone does not reveal whether a coin is XCH, a CAT or a singleton — that needs the puzzle, which this read never inspects — so naming one would assert a classification the node did not verify. A returned record MUST be bound to the id asked for: a coin id is self-certifying (`SHA256(parent ‖ puzzle_hash ‖ amount)`), so a source that answers with a DIFFERENT coin is a `WALLET_READ_FAILED` (§10) — never that coin's record, and never `coin: null`. `coin: null` MUST mean a chain source ANSWERED and reported no such coin; every way of failing to get an answer is a DISTINCT error (`WALLET_NO_CHAIN_SOURCE`/`WALLET_READ_FAILED`/`WALLET_RATE_LIMITED`, §10), NEVER a `null` — a `null` for an outage would tell a caller polling a mint that its coin does not exist, so a pending mint reads as awaiting forever. A caller MUST treat `null` as "not seen yet" and keep polling, not as "never happened". OPEN read (no token), same global fallback rate bound as the balance. `INVALID_PARAMS` on a missing/malformed `coin_id`, refused BEFORE any network call — an unanswerable question and a chain that answered "no" must never wear the same shape; the well-formedness rule is `dig-node-control-interface`'s own `WalletCoinByIdParams::validated()`, consumed rather than restated. Additionally `network_peak_height` (`u32` or `null`) and `stale_by` (`u32` or `null`), carrying EXACTLY their `control.wallet.balance` meanings (this section) and bound by the SAME null-versus-zero rule: `stale_by: 0` is a POSITIVE claim that this answer is level with the network, `null` is the OPPOSITE claim that nothing bounds it at all, and a consumer MUST NOT render the two alike. `stale_by` MUST be `null` unless BOTH this answer's `peak_height` and `network_peak_height` are known, and MUST saturate at zero rather than underflow. Both fields are ADDITIVE (§5.1). A consumer MUST NOT present `coin: null` as a statement about the CHAIN while `stale_by` is `null`: the replica may never have reached the height the coin was created at, so the only honest rendering is that THIS NODE has no record of the coin. The definite reading — no such coin exists on chain — is reserved for an answer whose tier can bound its own height. |
| `control.wallet.coinSpend` | `coin_id` (64 lowercase-hex, an optional `0x` prefix TOLERATED and normalized away) | `spend` (`{coin, puzzle_reveal, solution}` or `null`), `source`, `synced`, `peak_height` -- the tier fields carrying exactly their `control.wallet.coinById` meanings, and here always `"fallback"` / `false` / `null`: the local replica stores coin records, not spends, so it can never produce this answer. THE SPEND THAT SPENT ONE COIN, named by that coin's own id (a spend has no id of its own on chain). A coin record carries a puzzle HASH and says only that a coin is gone; the puzzle REVEAL and the solution exist only here, and they are what a caller reconstructing a lineage -- following a dig-profile's DID singleton forward -- needs. `coin` is the full record shape `control.wallet.coinById` returns, with `asset` ALWAYS `null` (this read classifies nothing) and `spent_height` ALWAYS non-null (a spend of a coin nothing calls spent is a contradiction; the node MUST fail closed rather than emit one). The node MUST verify that `puzzle_reveal` tree-hashes to `coin.puzzle_hash` and MUST refuse -- `WALLET_READ_FAILED` (§10) -- when it does not or will not parse: the reveal comes from an unauthenticated peer, a puzzle hash IS the reveal's CLVM tree hash, so the lie is locally detectable and a caller would otherwise curry a forged program into the spend it signs. The returned spend MUST be bound to the id asked for, by the same self-certifying coin-id recomputation `control.wallet.coinById` requires. `spend: null` MUST mean a chain source ANSWERED and holds no spend of that coin -- it is UNSPENT, or unknown; distinguishing those two is `control.wallet.coinById`'s job. Every way of failing to get an answer is a DISTINCT error, NEVER `null`: a caller walking a lineage reads "no spend" as *this is the tip* and stops, so a failure disguised as absence yields a spend built against a superseded singleton, and a mint poll reads it as "my funding coin is still there" and funds the same mint twice. OPEN read (no token), same global fallback rate bound. `INVALID_PARAMS` on a missing/malformed `coin_id`, refused BEFORE any network call; the rule is `dig-node-control-interface`'s own `WalletCoinSpendParams::validated()`, consumed rather than restated. Additionally `network_peak_height` (`u32` or `null`) and `stale_by` (`u32` or `null`), carrying EXACTLY their `control.wallet.balance` meanings (this section) and bound by the SAME null-versus-zero rule: `stale_by: 0` is a POSITIVE claim that this answer is level with the network, `null` is the OPPOSITE claim that nothing bounds it at all, and a consumer MUST NOT render the two alike. `stale_by` MUST be `null` unless BOTH this answer's `peak_height` and `network_peak_height` are known, and MUST saturate at zero rather than underflow. Both fields are ADDITIVE (§5.1). A consumer MUST NOT present `spend: null` as a statement about the CHAIN while `stale_by` is `null`, for the same reason `control.wallet.coinById` gives: a lineage walk reads an absent spend as *this is the tip* and stops. |
| `control.wallet.coinsByParent` | `parent_coin_id` (64 lowercase-hex, `0x` TOLERATED), optional `after_coin_id` (same rule), optional `limit` (1..=1000, default 100) | `coins` (array of the `control.wallet.coinById` record shape), `complete`, `cursor`, `source`, `synced`, `peak_height`. ONE PAGE of the DIRECT children created by spending the named parent. ONE HOP, never a walk: the node MUST NOT recurse -- a transitive walk over caller-supplied input is unbounded work the caller cannot bound, and a partial walk returned as complete is a lineage with a silent hole in it. A caller composes hops itself, pairing this with `control.wallet.coinSpend`. Children MUST be returned in ASCENDING `coin_id` order and that order MUST be stable across the pages of one walk, because `after_coin_id` means *strictly after this id in that order* and without a fixed order a cursor names no position (a walk would repeat some children and skip others). `complete` states whether the page is the WHOLE child set and MUST be derived from whether further children EXIST -- never from whether the page filled: the two differ exactly when the child count is an integer multiple of `limit`, where the second declares a truncated page whole and ends a lineage walk one hop early while looking finished. `cursor` is the LAST child in the page (the id the caller was handed), or `null` for an empty page; a node MUST NOT emit `complete: false` with `cursor: null`, which leaves a caller with no way to make progress. An out-of-range `limit` is REFUSED as `INVALID_PARAMS`, never clamped: the page boundary is what the caller resumes from, so a silently shrunk page hands back a cursor for a position the caller never asked about. Every record MUST report `asset: null` (naming a coin by its parent classifies nothing). Every child MUST name the requested parent; a source that returns one that does not fails the WHOLE read (`WALLET_READ_FAILED`, §10) rather than having the row filtered out. `coins: []` MUST mean a chain ANSWERED and the parent created no children it knows of -- typically it is unspent; every way of failing to consult a chain is a DISTINCT error, never an empty page, because an empty page reads as *that spend created nothing*. OPEN read (no token), same global fallback rate bound. `INVALID_PARAMS` on a missing/malformed id or an illegal `limit`, refused BEFORE any network call; the rules are `dig-node-control-interface`'s own `WalletCoinsByParentParams::validated()`. Additionally `network_peak_height` (`u32` or `null`) and `stale_by` (`u32` or `null`), carrying EXACTLY their `control.wallet.balance` meanings (this section) and bound by the SAME null-versus-zero rule: `stale_by: 0` is a POSITIVE claim that this answer is level with the network, `null` is the OPPOSITE claim that nothing bounds it at all, and a consumer MUST NOT render the two alike. `stale_by` MUST be `null` unless BOTH this answer's `peak_height` and `network_peak_height` are known, and MUST saturate at zero rather than underflow. Both fields are ADDITIVE (§5.1). `complete` scopes the PAGE and never the chain: it states that this node handed over every record IT found, while `stale_by` states how much of the chain that was. A consumer MUST NOT present `complete: true` as an unqualified claim that nothing was left out while `stale_by` is `null` — the node has just said it cannot bound its own answer's height, so the two must be read together. |
| `control.wallet.arrivals` | `after_seq` (integer ≥ 0, default `0`), `limit` (integer, default `50`, CLAMPED to `1..=500`) | `arrivals` (`[{seq, coin_id, puzzle_hash, amount, asset_id, confirmed_height}]`, oldest first), `cursor` (the RESUME position: the last `seq` actually returned, or the caller's own `after_seq` on an empty page), `latest` (the newest position the ledger holds). A client MUST resume from `cursor` and MUST NOT resume from `latest`: `latest` is read after the page, so an arrival recorded in between sits above the page and below `latest`, and resuming from `latest` would step over it. `latest` exists for the first-run case only — a client with no stored cursor reads it and passes it back as `after_seq` to start from NOW rather than replaying the ledger as a burst of notifications. INCOMING FUNDS the node determined ARRIVED, since a cursor (dig_ecosystem#2548) — the question neither `.balance` (a total the user's own change also moves) nor `.coins` (no notion of "new") can answer. A row is written ONLY for a coin that is (a) CONFIRMED — `confirmed_height` is `NOT NULL` in the store, so a mempool sighting is unwritable, not merely unwritten; (b) confirmed STRICTLY ABOVE the wallet's arrival baseline, which is armed ONLY by the statement that records a COMPLETED address-history catch-up — the one caller that has demonstrably replayed everything — so a first catch-up announces nothing, and a point read against the fallback oracle, which replays nothing, cannot arm a baseline at all; (c) not already recorded, enforced by a `UNIQUE` coin id on disk, so a restart, a reconnect or a rebuilt replica re-announces nothing; and (d) NOT created by spending a coin this wallet holds, so the user's own change is never reported as a receipt. `amount` is a decimal STRING (the full `u64` range; a JSON number would round it). `asset_id` is `null` for native XCH and the CAT's hex TAIL otherwise — NEVER a ticker, because naming an asset the node did not attribute would assert a classification it cannot support; a coin whose asset is not yet determinable is HELD and re-examined, never announced as XCH. A reorg DELETES the arrivals above the fork with the coins they describe, and walks the baseline back; `seq` is `AUTOINCREMENT`, so a deleted row's position is never reused and a stored cursor cannot come to mean a different arrival. `arrivals: []` means the node consulted its OWN replica and nothing arrived since the cursor — it is NOT a claim that the replica is current (ask `control.wallet.syncStatus`), and a node that has never completed a catch-up has no baseline and reports empty forever. OPEN read (no token) and the NARROWEST of the open reads: it touches only the local replica, has no oracle path, and so discloses nothing off-node and cannot amplify a poll into outbound requests. `INVALID_PARAMS` on a negative `after_seq`; `WALLET_READ_FAILED` if the local ledger cannot be read. The result additionally carries `synced` (bool), `peak_height`, `network_peak_height` and `stale_by` (`u32` or `null`), which describe the CHAIN REPLICA that WRITES this ledger rather than the ledger read itself. The ledger is local and cannot fail to be current with itself; what a reader needs bounding is the replica, because an empty page from a replica that is not following the chain is not evidence that nobody paid them. `synced` MUST be true only in the `synced` sync phase — the phase that licenses serving wallet-scoped reads from the replica — and `stale_by` obeys the same null-versus-zero rule as `control.wallet.balance`: `0` claims the ledger is level with the network, `null` claims nothing bounds it. A node that cannot read its own sync status MUST report `synced: false` with both heights absent. All four fields are ADDITIVE (§5.1). |
| `control.wallet.peak` | — | `peak_height` (`u32` or `null`), `synced` (bool). The node's current chain peak, independent of any address. Its OWN method rather than a field on a balance because a balance reports `peak_height: null` on every `"fallback"`-tier answer by design (§18.7b), so a caller bounding a claimed confirmation could not obtain one from the node that most needs to answer. Prefers the node's own replica and falls back to the chain tier. The chain tier is the node's OWN dialled Chia peers, asked CONCURRENTLY and settled on their AGREEMENT (NC-12): the height is the settled height every credible peer in the sample has passed, and a sample that collapses to one voice, or splits, MUST report `peak_height: null` rather than a repaired number. A node MUST NOT satisfy this read from a single public oracle, and MUST NOT fall through to one when its peers fail to agree — falling through would let one endpoint overrule the peers at exactly the moment corroboration failed, which is the single-source dependency NC-12 exists to remove. `peak_height: null` means UNKNOWN and MUST NOT be read as height zero, which every block is trivially above. `synced` carries EXACTLY its `control.wallet.balance` meaning (§18.7b) and MUST be MEASURED by the same predicate: a replica-served peak reports `synced: true` only while the replica is FOLLOWING the chain, so a behind-but-once-synced replica answers `synced: false` WITH its real `peak_height`, and a tier with no observable peer height, or a replica with no peak of its own, also answers `synced: false` — neither an unmeasured peer tier nor an unknown replica height can establish currency. A node MUST NOT derive this flag from `initial_sync_complete`, which latches on the first completed catch-up and is cleared only by a backwards chain move: a replica hundreds of blocks behind still satisfies it, so `control.wallet.peak` would report `synced: true` about the same replica `control.wallet.syncStatus` is simultaneously reporting as `syncing`. This is the endpoint a caller uses to bound a claimed confirmation, so the overstatement lands on the read that decides whether money has settled. A chain-tier answer reports `synced: false`, because a height the replica did not produce says nothing about the replica. OPEN read. |
| `control.wallet.resetCoinDb` | `confirm` (bool, MUST be `true`) | `coins_dropped` (`u64`), `staged_dropped` (`u64`). **DESTRUCTIVE.** Discards this node's chain-derived cache and forces a re-sync from chain. The node MUST clear the `initial_sync_complete` flag and the recorded coverage in the SAME transaction that empties the coins: that flag is what makes the local replica authoritative for wallet-scoped reads, so an emptied-but-still-synced replica answers `balance 0, synced true` on a funded wallet, and a crash between two separate writes would leave exactly that state. Reads then fall back to the chain tier until a genuine catch-up re-establishes the flag. No sync pass that was ALREADY RUNNING when the reset landed may re-establish it. The node MUST record a reset counter that the reset increments in that same transaction; every writer of `initial_sync_complete` — the address-history catch-up and the oracle-tier point-read refresh alike — MUST observe that counter BEFORE its own first write and present it again in the statement that sets the flag, which MUST NOT take effect if the counter has moved. Without that condition the reset and the sync pass are separate transactions that nothing serialises, and the interrupted pass marks the emptied — or partially refilled — replica synced one statement later: the same `balance 0, synced true`, or the likelier understated balance from a partial coin set. An address-history CATCH-UP whose completion is refused this way MUST report an error rather than success, so a fresh pass runs. The oracle-tier point-read refresh MAY instead log and return success, because it re-reads on its next call and has no pass to re-run; what it MUST NOT do is set the flag. A pass that began wholly AFTER the reset is unaffected and re-establishes the flag normally. It MUST discard chain-derived rows ONLY — never a seed, a device key, or any configuration a re-sync does not reproduce. It MUST REFUSE, writing nothing, while any spend is in flight, and liveness MUST be judged by EXPIRY against the node's own clock rather than by row presence: a lapsed hold that nobody has pruned MUST NOT deny the reset, and the instant MUST NOT be caller-supplied, since a far-future value would make every live hold read as expired. A refusal is an ERROR, never a success carrying a flag. `confirm != true` is `INVALID_PARAMS`. Token-gated (PAIRED tier: the DIG App drives this and holds a paired token, so reserving it to the master token would make it unreachable by its only consumer); loopback-only; NEVER an open read. |
| `control.wallet.broadcast` | `signed_bundle_hex` (lowercase hex, optionally `0x`-prefixed, of a chia `Streamable` `SpendBundle`) | `accepted` (bool), `transaction_id` (lowercase 64-hex or `null`), `rejection` (string or `null`). Pushes an ALREADY-SIGNED bundle. **§908: this method signs nothing and is never given anything it could sign with** — there is no key, seed, phrase or unsigned-plan parameter here and none may be added; on this surface the node's role is to read chain state and relay what somebody else signed. The node's OWN automated spends (§23, §25) never transit this method and are not reachable from it. A mempool that examined the bundle and refused it is a SUCCESSFUL call reporting `{accepted:false, rejection}`; failing to REACH a mempool is `WALLET_READ_FAILED`, and a node with no chain source is `WALLET_NO_CHAIN_SOURCE`. These MUST NOT be collapsed: the first says build a different bundle, the second says retry this one. `accepted:true` reports mempool admission ONLY and is NOT evidence anything reached a block — a caller MUST NOT record an outcome from it; only a buried confirmation of the created coin is evidence. `INVALID_PARAMS` on hex that is not a streamable `SpendBundle`, refused BEFORE any network call. A bundle requiring a signature from any key the NODE custodies — whatever puzzle wraps the coin — while `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off is `WALLET_NODE_SPEND_DISABLED`, also refused before any network call — the node relays what somebody ELSE signed, and it signs on request, so whether the node could have signed it is CHECKED rather than assumed. TOKEN-GATED (not an open read). |
| `control.chiaPeers.add` | `ip` (a bare IPv4/IPv6 literal — no brackets, no port, no hostname; the standard full-node port is assumed) | `{added: true, ip, port, corroboration_bypassed, notice}`. TRUSTS a Chia full node: it writes the `user_managed` peer row that is the ONLY way to reach `PeerTrust::Operator`, the trust level whose answers may drive catch-up, rollback and the `initial_sync_complete` flag WITHOUT a quorum. Every other peer is `Discovered` and must be corroborated by independently chosen peers first (§18.16). `ip` is CANONICALISED on the way in (`IpAddr` display form — RFC 5952 lowercase compressed for v6) and echoed back in that form, so one host is one entry however it was spelled; `INVALID_PARAMS` on anything that is not a bare literal, refused before any write. `corroboration_bypassed` is the RESULTING trust state, NOT a restatement of the request: a node MUST report `false` where the entry did not end up trusted — adding a peer that was BANNED un-bans it and confers no bypass. `notice` carries the cost as a sentence and MUST be non-empty, name the corroboration bypass, and be rendered VERBATIM; a client MUST NOT paraphrase, truncate or suppress it. The wording MUST authorise only **a node the operator runs themselves** — never vouching or recommending, which widen the case past what justifies the entry's unbounded authority. Idempotent — re-adding a known peer succeeds and un-bans it. A node MUST serve this from the SAME peer store its wallet replica consults. **MASTER-TOKEN TIER** (`ControlMethod::requires_master_token`): a paired token MUST be refused, because the entry outlives the token that wrote it and `pairing.revoke` removes no peer row. |
| `control.chiaPeers.list` | — | `{peers: [{ip, port, peak_height, user_managed, banned}]}` — every tracked Chia peer: TRUSTED, DISCOVERED **AND BANNED** alike. `user_managed` tells the trusted set from the discovered one and MUST be reported rather than filtered on: a list showing only the trusted set would let a person conclude the node talks to nobody else. `banned` MUST likewise be reported and its rows MUST NOT be omitted — this is the ONLY enumeration of the ban set, and a blocklist a person cannot read is a blocklist they cannot correct. This enumeration is DISTINCT from the dialling read, which excludes banned peers; a node MUST NOT serve both from one relaxed query. `peak_height` is `null` where the node holds no telemetry for that peer yet — `null` means UNOBSERVABLE and MUST NEVER be reported as `0`, which would render an unpolled peer as one stalled at genesis. A reported height is that peer's CLAIM, never a verified fact, and MUST NOT be aggregated into a chain position (NC-12). TOKEN-GATED at the ORDINARY tier — a read grants nothing that outlives the token, and a paired client must stay able to show the operator the trust state it is subject to. |
| `control.chiaPeers.remove` | `ip` (canonicalised as for `add`), optional `ban` (bool, default `false`) | `{outcome, ip, banned}` where `outcome` is `"removed"` or `"no_such_peer"`. Stops trusting a peer, RESTORING corroboration for it. There is deliberately NO `removed: true` companion field: this is the only way to un-trust a peer holding unbounded authority over the wallet replica, so a consumer MUST match on `outcome` and MUST surface `"no_such_peer"` as a failure to act — an operator told "removed" when nothing matched believes they revoked custody-grade trust and did not. Matching is by the canonical form, so an address spelled differently from the stored entry still names the same peer. `ban: true` keeps the peer excluded so discovery cannot re-add it; the banned set is bounded at `MAX_BANNED_CHIA_PEERS` (256) and on overflow a node MUST evict its OLDEST ban rather than refuse the newest. `ban: false` merely forgets the row and is the un-ban path — clearing a ban that way grants NO trust. `INVALID_PARAMS` on a missing or non-literal `ip`. **MASTER-TOKEN TIER** — a paired token MUST be refused, so it cannot strip the peers an operator deliberately trusts. |
| `control.peers.ping` | `peer` (a 64-hex `peer_id`, or a dialable `host:port` with IPv6 bracketed), `peer_id` (OPTIONAL 64-hex — pins the identity the presented certificate MUST derive) | The connection-ladder report — see §7.4a. `INVALID_PARAMS` on a missing/blank `peer`; `CONTROL_ERROR` when no peer network is running; `PEER_PING_REFUSED` (§10) when the anti-amplification gate refuses before dialing. |

### 7.4a. `control.peers.ping` — the connection-ladder diagnostic

Given a peer, the node MUST attempt EVERY rung of the §19.1 traversal ladder against it and report
each one, then grade the run. It answers "is this peer reachable, and HOW?" — the question a raw TCP
port probe cannot answer, since an open port says nothing about whether the mTLS handshake succeeds
or whether the certificate binds the identity asked for.

**Result shape.**

```json
{
  "peer": "<the argument as given>",
  "expected_peer_id": "<64-hex>|null",
  "verdict": "direct" | "relayed-only" | "unreachable" | "identity-mismatch" | "unresolved",
  "severity": "ok" | "warn" | "error",
  "summary": "<one line of plain language>",
  "ladder": [
    { "tier": "direct", "result": "connected", "remote_addr": "[2001:db8::1]:9444",
      "family": "ipv6", "observed_peer_id": "<64-hex>", "elapsed_ms": 41 },
    { "tier": "hole-punch", "result": "failed", "reason": "<dig-nat's own text>", "elapsed_ms": 5000 },
    { "tier": "upnp", "result": "unavailable", "reason": "<the local precondition that is missing>" },
    { "tier": "relayed", "result": "skipped", "reason": "overall deadline of 45s reached first" }
  ]
}
```

`tier` is one of `direct` / `upnp` / `nat-pmp` / `pcp` / `hole-punch` / `relayed`, in §19.1 rank
order with the relay LAST. A rung's `result` is one of `connected` / `failed` / `identity-mismatch` /
`unavailable` / `skipped`; only `connected`, `failed` and `identity-mismatch` carry `elapsed_ms`,
since the other two dialed nothing. `family` distinguishes `ipv6` from `ipv4`, so an IPv4-only
success is visible as the §5.2 finding it is.

**Normative requirements.**

- **Report the LADDER, not the winner.** Every rung MUST appear. A rung the deadline pre-empted is
  reported `skipped` with a reason, never dropped. Probing MUST NOT stop at the first success:
  "relayed succeeded" is only actionable next to "direct failed, and why".
- **"Not configured here" is NOT "failed there".** A tier the node cannot compose at all — UPnP with
  no local port mapping, NAT-PMP/PCP with no IPv4 gateway, hole-punch with no reflexive address or
  coordinator, relayed with no reservation — MUST be reported `unavailable`, with a reason naming the
  missing LOCAL precondition, and MUST NOT carry an `elapsed_ms` (nothing was dialed). On an ordinary
  node several rungs compose to nothing, so reporting them as failures would blame the peer for this
  node's configuration and show a healthy result as several red rows. `unavailable` never changes the
  verdict, which is decided only by what CONNECTED.
- **Identity outranks reachability — including over UNreachability.** When `peer_id` is known or
  pinned, a rung that reaches a certificate deriving a DIFFERENT `peer_id` MUST grade
  `identity-mismatch` / `severity: "error"`. Note the mechanism, because it inverts the naive
  expectation: dig-tls pins the expected id inside its certificate verifier, so a mismatch ABORTS the
  handshake and no connection is ever produced. The mismatch therefore arrives as a dial FAILURE, and
  an implementation that only inspects successful connections will report an impersonation — or a
  stale address-book entry — as `unreachable`, which is the reading a user would act on backwards. A
  rung MUST report `result: "identity-mismatch"` with the answering `observed_peer_id` where the
  handshake error discloses it; the classification MUST NOT depend on recovering that id. An explicit
  `peer_id` param always wins over what the node believes is at that address.
- **A relay-only success is `warn`, never `error`.** Most peers are behind NAT and are relay-
  reachable only; that is the normal shape of the network, and grading it as failure would report a
  healthy network as broken.
- **No anonymous dial.** dig-nat pins the expected `peer_id` in its TLS verifier, so an address the
  node cannot name an identity for MUST be answered `verdict: "unresolved"` explaining that `peer_id`
  is required — NEVER downgraded to a bare TCP probe, which would give exactly the "an open port
  means connected" answer this method exists to replace. Identities are resolved ONLY from the
  connected pool (mTLS-authenticated) or the caller's explicit pin.
- **Read-only on the DIG network.** Each rung's connection MUST be dropped as soon as it is graded:
  no pooled session, no announcement, no retained relay reservation, no stored state. One documented
  exception, because it is a real side effect: the UPnP rung is a PORT-MAPPING method, so composing it
  calls `add_port_mapping` and leaves a ~2h mapping on the operator's OWN router, once per ping. That
  is this node's NAT device rather than network state, and the ordinary dial ladder does the same on
  every peer dial — but it MUST NOT be described as "writes nothing".
- **Authorization: the control token, master OR paired.** `control.peers.ping` is a `control.*` method
  and is NEVER peer-reachable (absent from `dig_rpc_protocol::Method`, so the mTLS peer wire answers
  `-32601`) and never on the public-read allowlist. It is NOT a pairing-admin method, so a PAIRED
  controller token may drive it as well as the master token — deliberate, since a paired local UI
  (dig-app) is the intended consumer of the diagnostic and the method is read-shaped. Target
  restriction is a separate, tracked concern shared with `control.peers.connect`.
- **Bounded.** Each rung is bounded by the node's per-tier dial timeout (5s) and the run by an
  overall deadline (45s), so a black-holed address cannot hang the caller. A consumer MUST allow for
  the full deadline: this is the one control method that can legitimately take tens of seconds, and
  a client timeout below it would report a healthy ladder as a transport failure.
- **Not an amplifier.** The method makes the node dial a caller-supplied address, so it MUST be
  bounded: at most ONE ladder runs at a time, and at most 6 runs START per 60s. A refusal is
  `PEER_PING_REFUSED` (§10) and MUST NOT be reported as a ladder result — nothing was dialed. A
  refusal for concurrency MUST NOT consume rate budget, and an unresolvable argument MUST NOT
  consume it either.
- **One implementation.** The rungs MUST be dialed through the same NAT config builder every other
  node dial uses, narrowed only by `enabled_methods`, so the diagnostic cannot drift into a parallel
  prober that disagrees with what the node really does.

### 7.5. Ownership boundary

Cache and sync operations MUST proxy to the node library
(`cache_list_cached`/`cache_remove_cached`/`cache_fetch_and_cache`/`clear_cache`/
`set_cache_cap_bytes`/`cache_cap_bytes`/`cache_used_bytes`/`cache_usage`/`sync_whole_store`); the shell never duplicates read/cache
logic. The shell owns only the pin registry and the upstream override.

### 7.6. Pin registry

Persisted under the shell-namespaced `pinned_stores` key in `config.json` (§3.6) as an array of
`{ store_id, root? }` objects (lowercase 64-hex). `pin` is idempotent (re-pinning replaces the
entry, never duplicates); `unpin` of an absent store is a no-op reporting `unpinned: false`. Pins
survive cache eviction: a pinned-but-uncached store MUST still appear in
`control.hostedStores.list`.

### 7.7. Consumer conformance (the cross-repo parity contract)

A node controller is any local surface that queries or manages a running dig-node. All consume the
one interface above; what differs is only how far each reaches, gated by whether it can read the
same-host control token.

- **Open status/discovery surface (no token — every consumer, including a sandboxed web extension).**
  A consumer that cannot read a local file (a Manifest V3 browser extension, a visited web page) is
  limited to the UNGATED surface: `GET /health`, `GET /version`, `GET /.well-known/dig-node.json`,
  `rpc.discover`/`GET /openrpc.json`, and the read methods (`dig.*`/`cache.*`). This is sufficient to
  render node liveness, identity (service/version/commit), the bound addr, upstream, and cache
  cap/used. Node detection uses the §5.3 ladder (explicit `server.host` override > `dig.local` >
  `localhost:9778` > `rpc.dig.net`); the localhost tier MUST target the §3.2 default port `9778`.
- **Token-gated management (a same-host process controller).** The mutating + privacy-sensitive
  `control.*` methods require the control token from `<state_dir>/control-token` (§7.3/§7.3a). Only a
  process that can read that file — the DIG Browser "My Node" UI (a native process), the CLI, a local
  tool — can drive them. A sandboxed extension MUST NOT attempt to read the token; it MAY still CALL
  `control.status` and, on the canonical `-32030 UNAUTHORIZED` (§10), fall back to deep-linking a
  same-host controller for management. It MUST branch on the machine `data.code` (`"UNAUTHORIZED"`),
  never the numeric value alone.
- **`control.status` is the canonical status shape (a stable consumer contract).** A status consumer
  MUST be able to read these fields from `control.status` `result` (snake_case, additive-only): the
  store/capsule counters `hosted_store_count`, `pinned_store_count`, `cached_capsule_count`; the
  nested `cache.used_bytes` (and `cache.cap_bytes`); the nested `sync.available`; and `upstream`.
  Renaming or removing any of them is a breaking cross-repo change. The `control.status` field-name
  conformance is pinned by an integration test (`tests/server.rs`).
- **Lifecycle (start/stop/restart) is the CLI/OS-service contract, NOT an RPC.** A controller starts,
  stops, or restarts a node through the §8 CLI subcommands (`install`/`uninstall`/`start`/`stop`/
  `status`) and the §9 OS-service manager — never a `control.*` RPC (a node cannot RPC-restart itself,
  and lifecycle is an OS-service-manager concern). Liveness is observed via `GET /health` (`status:
  "ok"`) and `control.status` (`running: true`); `dig-node status` probes `/health` (§8.3). There is
  no `control.start`/`control.stop`/`control.restart`.

### 7.8. Integration-test launch surface

To let a consumer's end-to-end test exercise parity against a REAL node, `dig-node run` MUST bring up
a clean foreground node with zero out-of-band setup: it binds `127.0.0.1:$DIG_NODE_PORT` (default
`9778`), prints its readiness line to stderr, serves `GET /health` immediately, and exits gracefully
on Ctrl-C/SIGTERM (§9.5) so a test harness can `spawn → poll GET /health → drive control.* / read →
signal-stop`. `DIG_NODE_PORT` MUST be honored so a test picks a free port; `DIG_NODE_DIGLOCAL=0`
SHOULD be set in tests to skip the privileged `:80` dig.local bind. The control token for a
token-gated test is read from `<state_dir>/control-token` after startup; a test SHOULD set
`DIG_NODE_STATE_DIR` to an isolated temp dir (§7.3a) so its token/paired-token state is hermetic
regardless of any real machine-wide state dir on the host.

**The peer tier is NOT up when `/health` first answers (#1763).** The HTTP surface opens immediately,
while the peer network attaches seconds later, so a read issued as soon as `/health` responds skips
Tier 2 — reaching a configured upstream, or MISSING outright when none is configured (the default).
A harness that intends to exercise the P2P path MUST poll
`peer_tier.attached` on `/health` (§6.1) until it is `true` — a fixed sleep is neither sufficient nor
checkable — and MUST confirm `X-Dig-Peer-Tier: attached` on the response it measures (§4.6). A result
gathered from a response carrying `unattached` is a measurement of the gateway, not of peer replication.

### 7.9. Cache-method families (open `cache.*` vs gated `control.cache.*`)

The node exposes cache operations under TWO method families, BY DESIGN — a consumer picks the one
its transport/authorization permits. This is a deliberate dual surface, not a duplication to
collapse:

- **`cache.*` — open, node-engine-native (no token).** `cache.getConfig`, `cache.setCapBytes`,
  `cache.clear`, `cache.listCached`, `cache.removeCached`, `cache.fetchAndCache` — the node ENGINE's
  own cache RPC (dispatched by `dig_node_core::handle_rpc`, `served: "local"`, §5.5), reachable by
  any local consumer over `POST /` AND over the in-process FFI (`dig_rpc`) the DIG Browser's
  `chrome://settings` `DigCacheHandler` calls. Loopback-only is the only boundary; these are NOT
  token-gated.
- **`control.cache.*` — token-gated operator aliases.** `control.cache.get`, `control.cache.setCap`,
  `control.cache.clear` (§7.4) — the control plane's cache view/cap/clear, requiring the control
  token (§7.2). They wrap the SAME node-library cache operations behind the control-plane gate so a
  same-host process controller manages the cache through the one authorized `control.*` surface.

The name differences are intentional and STABLE: `getConfig`/`setCapBytes` are the engine's
long-standing FFI/RPC names; `get`/`setCap` are the control plane's terse aliases. Neither family is
renamed (backwards-compat). Guidance: a controller holding the token SHOULD use `control.cache.*`
(uniform control surface); a consumer without the token — a sandboxed extension, or the in-process
FFI — uses `cache.*`. `control.cache.get` mirrors `cache.getConfig`, `control.cache.setCap` mirrors
`cache.setCapBytes`, `control.cache.clear` mirrors `cache.clear`.

The full authoritative method + error set (both families, the `control.*` operator methods, and the
read/peer methods) is the one defined by this SPEC and mirrored in `SYSTEM.md`; consumers implement
SUBSETS of it (the extension drives `control.status` + `dig.getContent`; the browser a wider subset)
but MUST NOT diverge names or shapes. The eventual single shared home for this catalogue is the
`dig-rpc-protocol` crate (§1.4/§1.5); the node's dispatch + peer allowlist are adopted from it.

### 7.10. Cache LRU order + telemetry (#279)

The OPEN `cache.*` family is the surface a browser controller (the DIG Chrome extension's control
panel) uses to MANAGE how much disk space is reserved for cached `.dig` content under the node's LRU
eviction. These additive fields/methods complete that surface; all are `served: "local"`,
`requires_auth: false`, and additive-only (§5.1 — an older reader ignores the new fields).

- **`cache.listCached` — per-entry `lru_rank`.** Each entry in the `cached` array carries, beside
  `capsule` / `store_id` / `root` / `size_bytes` / `last_used_unix_ms`, an integer **`lru_rank`**:
  `0` is the LEAST-recently-used capsule (the NEXT one the size cap would evict), increasing with
  recency, forming a strict `0..n` permutation over the listed entries. The order is exactly the
  oldest-`last_used_unix_ms`-first order `plan_eviction` applies (ties broken by list position), so a
  controller renders the eviction queue directly without re-deriving it. `last_used_unix_ms` is the
  file mtime, bumped to now on every local serve.

- **The cap bounds the WHOLE cache, and is SPLIT across the evicting subtrees.** `cache_cap_bytes` is
  ONE budget over the entire cache tree, never a per-subtree limit. It is divided into a reserved
  **responses share** (`cap / 8`, for `<cache>/responses`) and a **modules share** (the remainder, for
  `<cache>/modules`); each eviction sweep spends only its own share, so the SUM on disk is bounded by
  the configured cap and `used_bytes` and `cap_bytes` describe the same thing. Reserving a share for
  responses (rather than letting modules take whatever responses leave) is required so the small
  regenerable response windows are not starved by whole capsules. Bytes under `<cache>/modules` that
  the scan cannot identify as a capsule are COUNTED against the modules share and MUST NOT be deleted:
  the bound is a bound on disk consumed, and the sweep does not exclusively own that directory, so
  recognised capsules are evicted to compensate for bytes it cannot remove.

- **`cache.setCapBytes { cap_bytes }` — the RESERVED cap.** Sets the reserved disk space for cached
  content, **floored at 64 MiB** (a `cap_bytes` below the floor is raised to it), and returns the
  applied `{ cap_bytes }`. `cache.getConfig` returns the live `{ cap_bytes, used_bytes, cache_dir,
  shared }`.

- **`cache.stats` — session cache telemetry (new).** Result:
  `{ cap_bytes, used_bytes, entry_count, total_bytes, evicted_count, evicted_bytes, refetch_count,
  content_cache: { hits, misses }, tiers: { tier0_precache, tier1_demand, tier2_bribed } }`.
  `entry_count`/`total_bytes` are the count and summed on-disk size of cached capsules;
  `evicted_count`/`evicted_bytes` are the disk-cache LRU evictions since the node started;
  `content_cache.hits`/`misses` are the decoded-content (RAM) cache lookups since start. All
  counters are process-lifetime (reset each start), never persisted. See §7.10e for
  `refetch_count` and `tiers`.

### 7.10e. Cache observability metrics (#1991, epic #1934)

`cache.stats` (§7.10) exposes the metrics a controller (the dig-chrome-extension control panel; the
relay-globe per-location cached-store count, #1933) needs to observe cache HEALTH, not just its
current contents. Each field is sourced from a REAL counter or, where the underlying signal does not
exist yet, an honestly-stubbed placeholder — never a fabricated number.

- **`refetch_count`** — whole-capsule NETWORK lands since process start: bytes actually pulled over
  the wire and written to disk, as opposed to a RAM decode-cache miss (`content_cache.misses`, which
  can hit an already-on-disk capsule with no network at all). There are exactly TWO landing write
  paths in the crate, and each bumps this counter once at its own successful write, together
  covering every genuine re-download with no overlap: `Node::sync_module_from` — the choke-point
  every ON-DEMAND path (`cache.fetchAndCache`, chain gap-fill, fetch-side backfill §7.10d(a))
  funnels through — and `module_reshare::promote_into_cache`, the reshare-warm land, which is a
  SEPARATE write-then-rename that never calls `sync_module_from`. A failed sync/promotion (no
  upstream reachable, verification rejected, a tampered/mismatched artifact) never increments it.

- **`tiers.{tier0_precache,tier1_demand,tier2_bribed}`** — per-`CacheTier` (§7.10a) occupancy, each
  shaped `{ occupancy, wired }`. `wired: false` means the tier has no live occupancy source yet — its
  `occupancy` is a fixed `0`, never a guess — and `wired: true` means the figure is real:
  - **`tier1_demand`** is **`wired: true`** today: `occupancy` is the inbound-demand ledger's
    (§7.10d) own bounded-LRU entry count — the number of DISTINCT stores currently tagged
    `Tier1Demand` by real peer/local demand. This needs no cache wiring to be honest; the ledger
    already tracks exactly this.
  - **`tier0_precache`** and **`tier2_bribed`** are **`wired: false`**: no tier-0 prefetch loop and
    no tier-2 bribed-retention mechanism exists yet (later epic-#1934 children), so there is nothing
    to count. The shape is fixed now (`occupancy`/`wired` fields present) so a controller written
    against it today needs no change when those children wire a real source — only `wired` flips to
    `true` and `occupancy` starts moving.

All `cache.stats` counters remain process-lifetime (reset each start, never persisted) and additive
(§5.1) — an older reader that does not know `refetch_count`/`tiers` still parses the fields it does.

### 7.10a. Cache relevance + tier model + eviction precedence (#1986, epic #1934)

The `relevance` module (`crates/dig-node-core/src/relevance.rs`) is the PURE, deterministic scoring
core the disk cache consults to decide WHAT is worth keeping, WHAT to sacrifice first, and WHEN a
fresh candidate may displace an incumbent. It performs NO I/O and reads NO clock — time enters only
as caller-supplied tick counters — so its decisions are reproducible and auditable. This subsection
specifies the contract; the live wiring into the on-disk LRU (§3.4/§7.10) is delivered by later
children of epic #1934 and is out of scope here.

**Tiers + eviction precedence.** Every cached entry belongs to a `CacheTier`:
`Tier0Precache` (speculatively fetched), `Tier1Demand` (fetched for a real local read), or
`Tier2Bribed` (retained because a backer paid). Cross-tier eviction precedence is fixed by the tier
ALONE — **tier2 > tier1 > tier0**, i.e. Tier0 is sacrificed first and Tier2 last — so speculative
precache can never evict content a user or a paying backer asked for. Relevance score orders entries
only WITHIN a tier, never across tiers. `evict_key(entry) -> (tier_rank, last_access_ticks)` yields
the eviction sort key: sorting entries by it ASCENDING gives exactly tier0-oldest → tier1-oldest →
tier2-oldest (LRU within each tier), which is the order the cap MUST evict in. `tier_rank` is
`Tier0Precache = 0`, `Tier1Demand = 1`, `Tier2Bribed = 2`.

**Relevance score.** `relevance(store: &RelevanceInputs, node: &NodeContext) -> RelevanceValue` is a
weighted sum:
`xor·proximity + scarcity·scarcity_term + demand·demand_term + recency·recency_term
+ pin_adjacent·[adjacent] + pinned·[pinned]`.

- **XOR proximity is the PRIMARY, ungameable signal.** Proximity is derived from
  `content_id XOR peer_id` and MUST be a strictly decreasing function of that distance (closer =
  higher). The reference map is `1 - (hi128 / 2^128)` over the top 128 bits of the distance. It is
  ungameable because an attacker cannot choose the victim's `peer_id` and cannot cheaply grind a
  `content_id` that lands near it (a 256-bit preimage search), so junk cannot be made to look like
  "this node's responsibility". Every other signal is a bounded ADDITIVE bonus.
- **Replication scarcity is CLAMPED (load-bearing anti-gaming).** `known_provider_count` is UNTRUSTED
  and MUST be clamped to `[1, 32]` before use; the resulting term lies in `[0, 1]` (fewer providers →
  higher) and is scaled by a weight strictly smaller than the XOR weight. A flooded count (→ `u32::MAX`)
  clamps to the ceiling (scarcity → 0) and a deflated count (0) clamps to the floor (scarcity → 1), so
  a lie can neither DOMINATE the score nor ZERO it — the XOR + demand terms survive regardless.
- **Local demand + recency + pin adjacency** are bounded additive bonuses: demand saturates at 16
  reads, recency decays as `1/(1 + age/1000)` (age in ticks; `None` ⇒ 0), and pin-adjacency adds a
  fixed small bonus. An explicit pin (`is_pinned`) adds a large bonus that deliberately overrides the
  heuristics (a pin is a direct operator instruction).
- **Weight invariant.** The default weights keep the XOR term strictly dominant over the sum of the
  gameable secondary bonuses, so proximity always leads.

**Displacement hysteresis.** `should_displace(incumbent, candidate, margin) -> bool` returns true
only when `candidate > incumbent + margin` (strict). The margin is an anti-thrash band: without it,
two near-equal stores would ping-pong in and out of the cache each sweep. At or below the margin the
incumbent stays.

### 7.10b. Tier-0 knapsack selector (#1988, epic #1934)

The `tier0_selector` module (`crates/dig-node-core/src/tier0_selector.rs`) is a PURE, deterministic
selector that decides WHICH speculative-precache candidates are worth keeping under a small
sub-budget, given each candidate's size and a relevance score already computed by §7.10a's
`relevance`. Like `relevance`, it performs NO I/O and reads NO clock. It does NOT sample the DHT for
candidates (a later epic-#1934 child) or fetch/evict anything against the live cache — that wiring
is out of scope here.

**Sub-budget.** Tier-0 speculative precache is bounded to `TIER0_BUDGET_FRACTION` (0.10) of the
node's WHOLE cache cap (`DIG_NODE_CACHE_CAP`/§7.10 `cache_cap_bytes`), never the whole cap —
`tier0_budget_bytes(whole_cache_cap_bytes) -> u64` computes this fraction as pure arithmetic over a
caller-supplied cap (the cap lookup itself is I/O and stays outside this module). Tier-0 is an
opportunistic bet, and reserving only a slice of the cap keeps it from crowding out real Tier1/Tier2
retention even before the tier-based eviction precedence (§7.10a) has to bite.

**Selection.** `select_within_budget(candidates: &[Candidate], budget_bytes: u64) -> Vec<usize>`
returns the indices of the candidates to keep, using GREEDY selection by value-density
(`relevance / size_bytes`, descending) rather than an exact 0/1 dynamic-programming knapsack — DP is
`O(n * budget)`, which is disproportionate at a GiB-scale budget; greedy is `O(n log n)` and
near-optimal (it can only under-fill the last unit of budget by at most one candidate's size). The
selected set's total size MUST NOT exceed `budget_bytes`. A candidate with `size_bytes == 0` is
treated as infinitely dense (free to keep) and is always included rather than causing a
divide-by-zero.

**Displacement hysteresis.** `should_displace_tier0(incumbent, candidate, margin) -> bool` is a
thin, named wrapper over §7.10a's `should_displace`, reusing its `candidate > incumbent + margin`
rule so tier-0 re-selection against an existing held set does not thrash a fetch/evict/refetch cycle
on marginal score differences. The tier-0 selector's own default margin is
`DEFAULT_HYSTERESIS_MARGIN` (0.05), overridable per call.

### 7.10c. DHT candidate sampling + anti-Sybil quorum reconciliation (#1987, epic #1934)

The `dht_sampling` module (`crates/dig-node-core/src/dht_sampling.rs`) produces the CANDIDATE SET that
feeds §7.10a's `RelevanceInputs` (each candidate's `content_id` + an untrusted `known_provider_count`).
It does NOT score candidates (§7.10a) or select/fetch them (§7.10b + the fetch child) — discovery and
reconciliation ONLY. It splits a PURE reconciliation policy from the network I/O so the
security-critical logic is unit-tested with no sockets.

**Observation model.** A `PeerObservation { peer_id: [u8;32], holdings: Vec<ObservedCandidate> }` is
ONE peer's reported provider view — the shape of a dig-dht `DhtService::provider_snapshot` (the RLY-009
`get_dht_records` view, #1935): each `ObservedCandidate { content_id: [u8;32], provider_count: u32,
size_hint: Option<u64> }` is that peer's untrusted claim about one content KEY (the 32-byte
`ContentId::to_key` keyspace point). The DHT provider snapshot carries no size, so `size_hint` is
optional; the true size is learned at fetch time.

**Random keyspace sampling.** `sample_keyspace_points(rng: &mut impl KeyspaceRng, k) -> Vec<[u8;32]>`
picks `k` keyspace points to probe. Randomness enters ONLY through the injected `KeyspaceRng`
(a self-contained non-cryptographic `SplitMix64` seeded from node state — MUST NOT be used for keys or
nonces), so coverage is deterministic under a seed. Points are reached in production with the dig-dht
routing primitive `find_node`/`known_closest`, which accepts ANY key — so sampling probes arbitrary
regions rather than only ids the node already holds, spreading coverage across the whole keyspace.
`DEFAULT_SAMPLE_POINTS` = 8.

**Anti-Sybil quorum reconciliation.** `reconcile(observations: &[PeerObservation], policy:
&QuorumPolicy) -> Vec<Candidate>` admits a content key ONLY when at least `policy.min_distinct_peers`
(`DEFAULT_QUORUM_MIN_PEERS` = 3) DISTINCT peers independently report it. Observations are collapsed per
peer FIRST — one peer listing a key many times (or across regions) is a SINGLE vote — so a lone
lying/Sybil peer's unique injections never reach the candidate set. Each admitted key's
`known_provider_count` is the LOWER MEDIAN of the reporting peers' claimed counts (NEVER the max): a
single peer inflating its count to `u32::MAX` moves only one tail sample and cannot drag the median
while honest peers outnumber it; the mirror deflation-to-zero attack fails the same way. `size_hint`
is the lower median of the supplied sizes, or `None`. Output is sorted by `content_id`. §7.10a's
`[1, 32]` provider-count clamp remains the final defense on whatever count survives here.

**Residual model (stated, not hidden).** Distinct-peer quorum is a COST MULTIPLIER, not proof of
honesty: an attacker minting `M` distinct mTLS identities that all corroborate one key still clears the
bar. That residual is bounded by the surrounding layers — keyspace sampling forces the attacker to
cover the whole space, the §7.10a XOR proximity primary means a corroborated junk key scores by an id
the attacker cannot grind toward this node, and the `[1, 32]` clamp caps the surviving count.

**Composition seam.** `sample_candidates(probe: &dyn NeighbourhoodProbe, rng, sample_points, policy)`
ties sampling + probing + reconciliation over a `NeighbourhoodProbe` seam (`observe_near(point) ->
Vec<PeerObservation>`), reconciling ALL probed regions TOGETHER so the quorum is whole-round.

**Concrete probe (`neighbourhood_probe` module, #1989 child 4a).** `DhtNeighbourhoodProbe` implements
`observe_near`: it routes toward `point` with dig-dht `find_node`, then for each returned `Contact`
opens/uses an mTLS peer connection and calls the `dig.getProviderSnapshot` peer RPC (§7.4 in
dig-node-core `SPEC.md`), turning each RESPONDING peer into ONE `PeerObservation`. Two properties are
normative and security-critical:

- **Identity comes from the verified session, never the wire.** A `PeerObservation.peer_id` is the
  anti-Sybil VOTE identity, so it is set from `SHA-256(verified mTLS server-cert SPKI DER)` of that
  session — NEVER from `Contact.peer_id` and NEVER from any field of the snapshot payload (the
  `DhtRecordsAnswer` is deliberately identity-free). A peer lying about its id in its `Contact` either
  fails the pinned handshake (contributing nothing) or is attributed to the cert it actually presented.
  An unreachable/silent/erroring peer yields NOTHING (never an error), matching the seam contract.
- **Volume caps before reconcile.** Each peer's holdings are truncated at `MAX_HOLDINGS_PER_PEER` (=
  the server's 512-key cap) and the whole round's observation volume at `MAX_OBS_PER_ROUND` (4 096),
  so neither a single verbose peer nor a Sybil cluster can exhaust memory in `reconcile`.

The server half — answering `dig.getProviderSnapshot` from this node's local provider store, counts
only, `max_keys` clamped — is specified in dig-node-core `SPEC.md` §7.4/§7.4a. The prefetch loop that
DRIVES the probe (selection, fetch, cache writes) is child 4b, not this module.

### 7.10d. Tier-1 caching triggers — fetch-side backfill AND inbound demand (#1990, epic #1934)

A store earns the `Tier1Demand` tier (§7.10a) — real, non-speculative demand, evicted only after all
`Tier0Precache` — from EITHER of two independent triggers. Both are the same conclusion ("this content
is genuinely wanted here") reached from opposite directions:

- **(a) Fetch-side backfill (SPEC §5.6 / §14.3b).** THIS node reads a resource it does not hold, is
  served it from another node/upstream, and background-pulls the whole `.dig` so its NEXT read is
  local. This is what THIS node fetched. It is gated `ReadOrigin::Local`: a REMOTE peer's read served
  through this node MUST NOT trigger it, or a stranger could drive this node into pulling + caching +
  DHT-announcing content of the peer's choosing (an amplification primitive).

- **(b) Inbound demand (this section).** A remote PEER asks this node to serve a resource from a store
  (a `dig.fetchRange`/`dig.fetchModuleRange` request over the peer surface). That request is direct
  evidence this node's keyspace neighbourhood WANTS the content, so the demanded store is recorded in
  the in-memory INBOUND-DEMAND LEDGER (`crates/dig-node-core/src/inbound_demand.rs`), which tags it
  `Tier1Demand` and bumps a saturating demand count. The ledger is the FIRST live tier-tagging: the
  on-disk LRU cache (§3.4/§7.10) keys entries by path and orders them by file mtime alone and carries
  NO per-entry acquisition tier, so this in-memory, process-lifetime map (never persisted, additive
  over the `.dig` format and the LRU layout) is the source the relevance demand term
  (`RelevanceInputs.local_read_count`, §7.10a) and the tier-based eviction precedence consult for
  peer-demanded stores.

**The ledger is BOUNDED (memory is not remotely amplifiable).** Recording is always-on and fed by a
remote peer's on-wire store id, and the format check accepts any 64-hex value (not only stores that
exist), so a peer could otherwise mint permanent entries from the 2^256 keyspace until the node OOMs.
The ledger MUST therefore be a bounded LRU: at most `MAX_DEMAND_ENTRIES` (default 65_536) distinct
stores, evicting the least-recently-demanded entry on overflow (a re-demanded store is refreshed and
survives over colder entries). Worst-case memory is bounded by the cap — on the order of ten-odd MiB
— REGARDLESS of remote request volume; distinct-id spam churns through the fixed footprint rather
than growing it.

**What is always on vs. opt-in.** Recording inbound demand (the count + `Tier1Demand` tag) is
UNCONDITIONAL — it moves no content bytes and pulls no capsule, and its memory is bounded by the cap
above, so it carries no bandwidth/content amplification risk and always runs. The whole-`.dig` PULL on
inbound demand is OPT-IN, default OFF, gated by
`DIG_NODE_INBOUND_DEMAND_CACHE` (only an explicit `on`/`1`/`true`/`yes` enables it). A peer-triggered
pull is an amplification primitive of exactly the shape trigger (a)'s `ReadOrigin::Local` gate exists
to close.

**XOR-proximity admission on the pull (ENFORCED, #2014).** The opt-in pull is gated a SECOND time by a
keyspace-proximity admission that binds even when the flag is on: the pull fires ONLY when the demanded
capsule's DHT key (`ContentId::capsule(store_id, root).to_key()`) lies in THIS node's keyspace
neighbourhood — its XOR proximity to the node's own `peer_id` clears
`relevance::INBOUND_DEMAND_MIN_PROXIMITY` (the keyspace midpoint, `0.5`: the content id is closer to
this node's `peer_id` than a uniformly-random point, i.e. shares the top keyspace bit). This is the
same `xor_proximity` primitive and the same reference `peer_id` the tier-0 precache selector (§7.10a /
§7.10b) scores against, so both paths share ONE neighbourhood definition. What the gate binds — and
what it does NOT: an attacker cannot move this node's `peer_id`, so the gate confines peer-steerable
demand-caching to keys NEAR this node's own identity — never an arbitrary far-keyspace target. It does
NOT make naming a near key cost an on-chain mint: a peer may name any `(store, root)` whose key falls
near our `peer_id` and, on an opted-in node, drive a CHEAP DHT provider-lookup for it (a key that names
no real store simply finds no providers and the pull fails there — the low cost is "no providers", not
a per-key mint). The on-chain-mint + merkle cost binds a LATER step — actually becoming a cached
HOLDER: a pulled module is bound to its `root` by merkle verification — the admit gate
(`ChainAnchoredModuleVerifier`, shared by the reshare-admit pull AND the `cache.pushCapsule` land via
`verify_capsule_integrity`) RECOMPUTES the merkle root from the capsule's own SERVED CONTENT (per
`KeyTable` entry, `leaf = resource_leaf(concat_output(its ChunkPool ciphertexts))`, leaves sorted
ASCENDING by `static_key`, folded via `MerkleTree::from_leaves`) and refuses (`NotAnchored`) unless it
equals the committed `CurrentRoot`. The attacker-supplied `MerkleNodes` digests are NEVER trusted for
the admit decision (only cross-checked for served-proof consistency): trusting them let a single-leaf
`MerkleNodes = [chain_root]` plus an empty/garbage `ChunkPool` recompute to the committed root for free
and admit a contentless phantom-holder capsule (#2246/#2240). So a header-matching but
tampered/incomplete `.dig` (or one with an absent `KeyTable`/`ChunkPool`, an out-of-range chunk index,
or an undecodable section) is never admitted; a legitimately EMPTY store folds to `sha256(&[])` and is.
It is never SERVED as current
unless `root` equals the chain-anchored tip (the serve-time read-path pin, §7.10d(a) / §14.4). So the
worst a near-key attacker extracts from an opted-in node is a bounded, single-flighted, byte-capped
pull of REAL near-neighbourhood content of a possibly-old generation — never caching of fabricated,
junk, or out-of-neighbourhood content. The gate FAILS CLOSED: a node with no known self-identity (the
FFI/consumer path) or a non-canonical `(store, root)` admits no pull. The read itself is still served normally — the gate governs only the demand-driven
CACHE. The DEFAULT stays OFF; flipping it on (and any tightening of the midpoint bar toward a
routing-aware k-closest test, which depends on live network size) is a separate deliberate pass.

**Shared pull machinery.** When the opt-in pull fires, it reuses the SAME whole-capsule backfill body
as trigger (a) (`Node::spawn_capsule_backfill`): the `DIG_NODE_BACKFILL_ON_MISS` kill switch + a live
P2P content engine, an owned self-reference to spawn the detached task, a concrete `(store, root)`, an
already-held skip, and the ONE shared `(store, root)` single-flight acquisition gate (§21.3 / #1614) —
so both tier-1 triggers and the reshare warm can never drift in how they pull, dedupe, verify, or
announce, and an already-held store is never re-pulled.

### 7.10f. Tier-0 eager-precache loop — the governed round (#1989 child 4b, epic #1934)

The `tier0_prefetch` module (`crates/dig-node-core/src/tier0_prefetch.rs`) is the GOVERNED
orchestration that turns the DHT-sampling flywheel into actually-cached speculative content. It ties
the pure/seam pieces — §7.10c sampling+reconcile, §7.10a relevance, §7.10b knapsack selection — into
one self-driven ROUND: `sample_candidates` → size resolution → relevance score → `select_within_budget`
→ governed fetch (merkle-verify + hard byte-cap + cache tagged `Tier0Precache` + announce). The loop
is self-driven (it reads NO attacker-supplied trigger), so it is not the amplification vector the
inbound-demand pull (§7.10d(b)) is; every value an attacker can influence (they populate DHT provider
snapshots) is nonetheless bounded BEFORE it costs bandwidth or disk. The following governors are
NORMATIVE:

- **Off-switch, DEFAULT-ON.** `tier0_precache_enabled()` reads `DIG_TIER0_PRECACHE`; the loop is ON
  unless an explicit falsy value (`0`/`off`/`false`/`no`, case-insensitive) disables it. DEFAULT-ON is
  the deliberate stance for a self-driven, quorum-corroborated, XOR-relevant, byte-capped pull (unlike
  the inbound-demand pull, which is default-OFF because it is peer-triggered). `run_round` takes the
  resolved enablement as an injected `bool` parameter (the caller reads the env once per round), so the
  round is a pure function of its arguments.
- **Small-disk no-op (#1927).** `should_run_loop(cache_cap_bytes)` is `false` when the derived tier-0
  sub-budget (§7.10b `tier0_budget_bytes`, 10% of cache) is below `MIN_USEFUL_TIER0` (64 MiB); the
  caller checks this ONCE at bring-up and does not spawn the loop, degrading gracefully on a tiny disk.
- **Backoff-when-serving.** A round yields ENTIRELY (`RoundSkip::Busy`) when the `LoadSignal` reports
  the node is serving real inbound reads — speculative precache always defers to genuine demand.
- **Rate limit.** `RoundRateLimiter` is a token bucket on BOTH stores/window AND bytes/window (bytes is
  the load-bearing limit; bandwidth is the real cost). A fetch proceeds only when both buckets admit it,
  atomically (a refused byte-take never consumes a store token).
- **Size resolution — NEVER zero an unknown.** A candidate's size is the reconciled median `size_hint`
  when present; otherwise an ADMITTED candidate spends at most ONE bounded metadata probe (capped at
  `MAX_SIZE_PROBES_PER_ROUND` = 32 per round), else it is DROPPED for the round. An unresolved size is
  never treated as 0 (which would make it maximally dense in the knapsack).
- **Hard byte-cap at fetch.** Each selected store is fetched under a hard cap of
  `min(reported_hint, remaining_sub_budget)`; the fetcher enforces the TRUE store size against that cap
  and ABORTS + discards an over-size store (`DiscardReason::ExceededByteCap`) — the
  under-report-size-then-bloat defence. The selected total never exceeds the tier-0 sub-budget.
- **Merkle-verify before cache; never execute.** The fetch reuses the existing verified download path,
  so content is verified against the confirmed root before it lands and is never opened/executed;
  verification failure discards (`DiscardReason::VerifyFailed`).
- **Tier precedence.** Cached stores are tagged `Tier0Precache` and sacrificed FIRST. `effective_tier`
  is the MAX-across-ledgers rule (§7.10a `CacheTier::rank`): a store this loop precached that a peer
  later demands is promoted to `Tier1Demand`, so precache can never evict genuinely-demanded content.
- **Anti-Sybil identity carries forward from §7.10c/4a unchanged** — candidates come ONLY from
  `sample_candidates`, whose votes are attributed to the probe's mTLS-verified session `peer_id`.

**Size + wiring status (normative gap — the fetch seam's preimage requirement).** `run_round` is
complete as the governed orchestration over three concrete seams: `SizeProbe`, `Tier0Fetcher`, and
`LoadSignal`. A candidate carries a DHT `content_id` = `SHA-256(ContentId::canonical_bytes)` (§7.10c) —
a ONE-WAY key. Every merkle-verified fetch path (`find_providers`/`fetch_resource`/
`Node::gap_fill_generation`) is addressed by the `ContentId` PREIMAGE `(store_id, root)`, and merkle
verification itself requires the confirmed `root`. A concrete `Tier0Fetcher` therefore REQUIRES a
`content_key → (store_id, root)` resolution that the counts-only `dig.getProviderSnapshot` surface
(§7.10c, §7.4a) deliberately does not carry, and that the node otherwise holds only for stores it
already knows (subscriptions/chain-watch §7.10c/§14.2). That resolution is supplied by the
`dig.resolveCapsule` peer RPC (dig-node-core `SPEC.md` §7.4): a HOLDER answers a one-way `content_key`
with the verifiable `(store_id, root, size_bytes)` preimage it recomputes from its own holdings
(`ContentId::capsule(store, root).to_key()` equals the requested key), disclosing only the preimages of
capsules it already publicly provides. The SERVER half of that resolve is child PR-1 of the flywheel
live-wiring; the client resolver and the `Tier0Fetcher`/spawn wiring that consume it are the following
children (PR-2/PR-3). Until those land the governed round + its seams are the normative contract,
exercised end-to-end against injected seams.

### 7.11. Control-token pairing for browser controllers (#280)

An MV3 browser extension cannot read the `<state_dir>/control-token` file, so it cannot drive
token-gated `control.*` mutations. PAIRING lets it obtain its OWN scoped, revocable controller token
after LOCAL operator approval, WITHOUT ever exposing the master token. Two OPEN bootstrap methods +
three MASTER-gated administration methods, all loopback-only.

**OPEN methods (no token):**

- **`pairing.request { client_name }`** → `{ pairing_id, pairing_code, expires_ms }`. Creates a
  PENDING pairing. `pairing_id` is a 32-hex secret returned only to the requester; `pairing_code` is
  a 6-digit compare-codes value the requester DISPLAYS. Pending requests expire after 5 minutes; the
  node caps concurrent pendings (oldest evicted past the cap).
- **`pairing.poll { pairing_id }`** → `{ status, token? }` where `status` ∈
  `"pending" | "approved" | "expired" | "unknown"`. On `"approved"` the minted `token` is returned
  and the pending entry is CONSUMED (the token is delivered exactly once). The extension stores the
  token and presents it as `X-Dig-Control-Token` on subsequent `control.*` calls.

**MASTER-token-gated administration** (a paired token is NEVER accepted here — §7.2):

- **`control.pairing.list`** → `{ pending: [{ pairing_id, pairing_code, client_name, created_ms,
  expires_ms }], tokens: [{ id, client_name, created_ms }] }`. The token VALUE is never listed.
- **`control.pairing.approve { pairing_id }`** → `{ approved: true, client_name, token_id }`. Mints a
  fresh 64-hex scoped token, PERSISTS it to `<state_dir>/paired-tokens.json` (§7.3a, restricted,
  atomic), and marks the pending entry approved so the requester's next `pairing.poll` returns it. Approval is
  the CONSENT step: it requires the master token (a local file read), so only the machine's operator
  can grant a pairing.
- **`control.pairing.revoke { token_id }`** → `{ revoked: bool, token_id }`. Removes the token; the
  gate rejects it on the very next request (the store is consulted per request).

**Flow (compare-codes consent).** (1) The extension calls `pairing.request` and shows
`pairing_code`. (2) The operator runs `dig-node pair` (which reads the master token), sees the
pending request + its code + `client_name`, CONFIRMS the code matches the extension, and runs
`dig-node pair approve <pairing_id>`. (3) The extension's `pairing.poll` returns its scoped token.
(4) The extension drives `control.*` mutations with it. `dig-node pair revoke <token_id>` undoes it.

**Security properties (MUST hold).** Loopback-only, same as `control.*`. Approval requires the master
token, so consent is gated on local-machine control; the compare-codes step defeats a concurrent
rogue request (a visited page's) being approved by mistake. The `pairing.poll` response carrying the
token is readable only by an allowed CORS origin (`chrome-extension://…`, §4.3) — a foreign web
origin is CORS-blocked from reading it (and blocked at preflight from sending a `control.*` token
header). A paired token is SCOPED (it authorizes `control.*` mutations but not pairing administration)
and REVOCABLE. All token comparisons are constant-time.

**Paired-token store.** `<state_dir>/paired-tokens.json` (§7.3a) = `{ "tokens": [{ id, token,
client_name, created_ms }] }`, restricted (dir ACL), atomic writes. The auth gate accepts the master token OR any token in
this store (except for the pairing-administration methods).

### 7.12. Paired-token authorization for wallet methods (#370)

The pairing framework (§7.11) authorizes `control.*` mutations. The thin-client model (epic #365)
extends the SAME paired-token gate to the **wallet method surface**: over the authorized loopback
surface, every wallet MUTATION requires the master control token OR a valid paired token; an
unauthorized caller (no token, a wrong token, or a revoked token) is rejected with `-32030
UNAUTHORIZED` before the method runs.

**Gated wallet methods (MUST present a token).** The mutation group — the send/spend group (§18.9), the
offer suite + DID/NFT mint & transfer (§18.9a), and the state-changing record-update actions (§18.16).
These methods are NEVER relayed upstream — a signing request must never leave the loopback node; an
authorized call is served locally (or, until the wallet surface is served on a given transport, returns
a catalogued error — it is never proxied to the public gateway).

**The gate binds EVERY transport into the wallet handler set, and the binding MUST be structural
(dig-node#257).** The tier is a property of the CAPABILITY, never of the transport a caller reached
it through. The Sage-parity mTLS listener authenticates with a shared client certificate whose DER
must equal the server's own; that authenticates the transport and MUST NOT be treated as
authorizing a capability. A node MUST NOT serve any route into the wallet handler set without first
obtaining an authorization decision for the requested method name — including for a method name the
node does not implement, so a future method cannot arrive ungated.

This MUST be enforced by construction rather than by a per-route check: the router is built with an
authorization gate as a REQUIRED parameter, there is exactly one handler behind the method route,
and the only gate the transport crate itself offers denies everything. A per-route test set cannot
see a route nobody wrote a test for, which is how this listener came to serve custody, spends and
master-tier peer mutations on certificate possession alone.

A refused call MUST be answered `401` and MUST NOT reach the handler, so a refused spend has not
been built or broadcast. The refusal MUST be distinguishable from "no such method".

**Retired namespaces (`wallet.*`, `auth.*`) MUST be refused outright.** Node-side USER custody and its
unlock-auth gate were removed by dig_ecosystem#1701, superseded by the #1500 ratification: the node holds
no user spend key. No method exists under either prefix, and a node MUST classify the whole prefix as
retired and DENY it before consulting any token — a retired namespace that fell through to the open class
would leave a future `wallet.anything` unauthenticated by default, so the removal would have relaxed the
gate. Neither prefix appears in OpenRPC discovery.

`control.wallet.*` is NOT affected and MUST keep working: those are the light-client CHAIN READS
(`control.wallet.balance` / `.coins` / `.peak` / `.syncStatus` / `.broadcast`), which hold no key. The
distinction is the bare prefix — a control read is named `control.wallet.balance`, never `wallet.balance`.

**Master-token-tier wallet methods (a paired token MUST be refused).** A Sage-parity method name that
is an ALIAS for a master-tier `control.*` capability inherits that tier: `add_peer` is
`control.chiaPeers.add` and `remove_peer` is `control.chiaPeers.remove` — the same writer, the same
`user_managed` row, the same authority surviving `pairing.revoke`. A node MUST resolve the tier from the
CAPABILITY and not from the plane a caller reached it on, on EVERY transport (`POST /{method}` and
`/ws`); it MUST NOT enforce the tier on the `control.*` plane alone, which enforces nothing, since the
parity name reaches the identical writer one URL away. A node MUST derive both answers from the one
published predicate (`ControlMethod::requires_master_token`) rather than restating the tier per plane,
and MUST pin the two planes' answers for a capability in a SINGLE conformance assertion — a per-plane
test set cannot observe them diverging.

**Open wallet methods (no token).** Wallet READ methods (`get_*`) follow the read plane (§7.2): open to
local consumers. The recommendation of epic #365 is that the whole wallet WS session be paired-gated once
the bidirectional WS transport (#369) carries it; the security-critical MUST is that no mutation or
custody op ever runs unauthorized.

**There is no seed egress, because there is no seed.** The node holds no user seed and exposes no
mnemonic reveal on any surface — RPC, self-origin, or CLI (dig_ecosystem#1701, §908).

**Classification is pure + tested.** `wallet_authz::classify` maps a method to its class
(read | mutation | master-only | retired | non-wallet) and `wallet_authz::authorize` decides allow/deny,
unit-tested exhaustively: an unpaired caller is denied on every mutation method; a retired name is denied
with ANY token; a paired token
authorizes a mutation but NOT a master-tier capability under either of its names; a revoked token is
denied on the next request.

### 7.13. DIG auto-update beacon proxy (`control.updater.*`, #515)

The DIG auto-update beacon (`dig-updater`, a separate installable service — DIG-Network/dig-updater
SPEC §§1–13) checks daily for new releases of the DIG binaries and installs them behind a signed
trust chain. dig-node exposes a THIN proxy to it over the SAME `control.*` gate (§7.2) — it never
re-verifies the beacon's signed manifest and never decides what to install; it only reads the
beacon's world-readable status mirror and shells its own elevation-gated CLI.

| Method | Params | Result (essentials) |
|---|---|---|
| `control.updater.status` | — | `installed: false` when the beacon has no status.json yet (never an error); else `installed: true`, `status` = the beacon's `status.json` verbatim (dig-updater SPEC §13.2: `schema`, `version`, `channel`, `paused`, `paused_until`, `last_check`, `last_check_kind`, `last_outcome`, `last_reason`, `last_detail`, `components[]`, `next_wake`, `trust_state`) |
| `control.updater.setChannel` | `channel` (string: `"nightly"` or `"stable"`; `"alpha"` is a deprecated alias for `nightly`) | The beacon CLI's `channel set <channel> --json` output verbatim (dig-updater SPEC §13.3). Thin passthrough — the token is forwarded VERBATIM and the beacon CLI is the sole validator; an unknown token is forwarded and its decline surfaces as `CONTROL_ERROR` |
| `control.updater.pause` | `until?` (unix seconds) | The beacon CLI's `pause [--until <ts>] --json` output verbatim |
| `control.updater.resume` | — | The beacon CLI's `resume --json` output verbatim |
| `control.updater.checkNow` | — | The beacon CLI's `check --now --json` output verbatim — a full pass; the call blocks until it completes |

**Status is read directly off disk, never through the CLI** — `control.updater.status` is the
method a controller polls, and a file read is far cheaper than a process spawn on every poll. The
status directory is a WORLD-READABLE sibling of the beacon's own Admin/SYSTEM-only state directory
(dig-updater SPEC §13.2: `%ProgramData%\DIG\updater-status` on Windows, `/var/lib/dig-updater-status`
on Unix), so dig-node needs no elevation to read it. A present-but-corrupt `status.json` is reported
as `CONTROL_ERROR` (a genuine anomaly); an ABSENT one is `{ "installed": false }` (the beacon may
simply never have been installed on this machine) — never an error either way.

**Mutations shell the `dig-updater` CLI** — `setChannel`/`pause`/`resume`/`checkNow` invoke the
already elevation-gated operator CLI (dig-updater SPEC §13.3: `channel set`/`pause`/`resume` require
Administrator/root) rather than writing the beacon's Admin-only `config.json` directly. This service
runs privileged (Windows LocalSystem / a root daemon), so it satisfies that elevation check the same
way a human operator running an elevated terminal would. The CLI is resolved by an ABSOLUTE path —
an explicit override, else beside this running `dig-node` binary (the shared bin dir dig-installer
places `digstore`/`dig-node`/`dig-dns` into, and where the beacon installer, #514, is expected to
place `dig-updater`), else a per-OS conventional install root — NEVER a bare name resolved through
`PATH`. No binary resolves → `NOT_SUPPORTED` ("the DIG auto-update beacon is not installed on this
machine"); the CLI runs but declines (a bad channel, a missing elevation) → `CONTROL_ERROR` carrying
the CLI's own `detail` message; the CLI produces unparsable output (a crash) → `CONTROL_ERROR`.

**Opaque passthrough by design.** Both the status file and every CLI `--json` result are forwarded
as opaque JSON, never re-typed into a dig-node-owned shape — the beacon's schema-versioned wire
contract exists precisely so an independent reader can do this safely: a field the beacon adds later
passes through unchanged, with no shape to keep in sync on this side.

### 7.14. Always-on self-heal driver (#584 beacon re-arm + #651 ext-forcelist reconcile)

On a **privileged service run** (Windows LocalSystem / a root daemon), dig-node MUST run a detached,
best-effort self-heal driver: one pass on startup, then a pass every `SELF_HEAL_TICK` (**6 hours**).
It is NOT run on a dev/CLI (non-service) run. A pass performs two independent repairs; neither
failing ever blocks the serve path or the other repair:

- **Beacon re-arm (#584).** Kicks `dig-updater schedule ensure --json` — the idempotent verb
  (dig-updater ≥ v0.13.0) that re-registers a provably-ABSENT daily schedule. This closes the
  chicken-and-egg where an already-dead schedule cannot resurrect itself because nothing runs the
  beacon. `schedule ensure` itself respects a DELIBERATE opt-out (dig-updater writes an Admin-only
  sentinel on `schedule uninstall`; `ensure` short-circuits to `SuppressedByOptOut`), so dig-node
  keeps NO sentinel of its own — kicking `ensure` never re-arms an intentional uninstall.
- **Ext-forcelist reconcile (#651).** Reads the persisted channel (`dig-updater channel get --json` →
  `{ "channel": "stable"|"nightly" }`) and re-applies it to every detected browser via `dig-installer
  --set-ext-forcelist-channel <channel> --json` (idempotent). This recovers the post-remove-failure
  uninstall gap in the #613 staged channel switch (a crash after REMOVE but before RE-ADD leaves the
  extension uninstalled with the new channel already persisted, so an operator's `channel set` no-ops
  `Unchanged` and never retries).

**Security — absolute, privileged-root resolution only (#565 LPE).** Because the service spawns these
binaries with SYSTEM/root privilege, the sibling CLI MUST be resolved by an ABSOLUTE path beside the
running `dig-node` binary (the admin-only #565 install root), and that root MUST be REJECTED when it
is user-writable — on Unix a non-root owner or any group/world write bit; on Windows an owner other
than SYSTEM/Administrators. Resolution NEVER consults `$PATH` and NEVER accepts a bare name. A missing
sibling or a user-writable root is a benign/logged skip, never a spawn. The user-writable-root check
is the SAME spawn-free owner gate the TLS-root check uses (§4.1a) — one shared owner check, so the
two never drift.

**Bounded per-child timeout (#693).** Every self-heal child spawn (`dig-updater`/`dig-installer`)
carries a bounded wall-clock timeout (120 s). A hung child (a wedged scheduler API, a stuck policy
write) is cancelled and reported as a failed kick, so it can never block the pass or starve future
6-hourly ticks — the pass logs the timeout and continues, and the serve path is never affected.

### 7.15. Engine-side identity session (NODE-1 / U2, #910, #1080)

The engine exposes a transport-agnostic session half (`dig_node_core::session`) that verifies an
identity-authenticated IPC session on behalf of the `control.session.*` handshake. The engine is
**identity-agnostic**: it holds NO user signing key and can NEVER mint a signature with one. A dig-app
proves possession of a profile's slot-`0x0010` identity key; the engine only VERIFIES that proof and
tracks the resulting session in memory.

**Contract source of truth — `dig-ipc-protocol` (#1080).** The session/signing wire contract
(the `EngineSessionRegistry` state machine, the domain-separated message builders, the
`control.session.*` JSON-RPC types, the resource bounds, and the frame transport) is owned by the leaf
crate **`dig-ipc-protocol`**, the SINGLE source of truth shared byte-identically with the app half
(dig-app). `dig_node_core::session` RE-EXPORTS the crate's engine role-half at the established module
path and adds the engine's own **production** `DidSigningKeyResolver` (below). The two halves consume
one crate rather than each maintaining a copy, so they can never silently drift; a KAT cross-check
pins the crate's builders to the frozen golden bytes.

**Production DID resolver (#1080, over dig-identity #778).** `ChainDidSigningKeyResolver<S: ChainSource>`
resolves a profile DID to its published slot-`0x0010` key by CHAIN-AUTHENTICATED on-chain lookup,
delegating to `dig_identity::resolve_bls_public_key` (WU3): it walks the DID singleton lineage to its
authentic tip, finds the DID-paired store, binds the fetched profile body to the store's current
on-chain root, and returns the published key — failing CLOSED (`None`) on every ambiguity, staleness,
or mismatch. It never echoes the caller-presented key and never accepts a caller-supplied lineage; the
`ChainSource` it is built over MUST be a genuine forward lineage walk (coinset / full node), NEVER a
`SingletonLineage::single` echo. The concrete engine `ChainSource` (a coinset / full-node backed
DataLayer store-discovery reader) and the `control.session.*` WIRE transport (the per-user pipe/UDS +
its ACL, enforcing the re-exported frame bounds) remain the NODE-1 engine-carve follow-up.

**Domain-separated signed messages (byte-identical across halves, HARD RULE).** Two, and ONLY two,
messages are signed by the identity key. Their builders (now the `dig-ipc-protocol` builders) MUST
agree byte-for-byte with dig-app's half (a shared KAT proves it):

- **Attach challenge:** `SESSION_CHALLENGE_DOMAIN ‖ nonce ‖ profile_did`, where
  `SESSION_CHALLENGE_DOMAIN = "DIGNET-SESSION-v1"` and `nonce` is 32 bytes of OS randomness.
- **Sign callback:** `SIGN_CALLBACK_DOMAIN ‖ len16(payload_type) ‖ payload_type ‖ payload`, where
  `SIGN_CALLBACK_DOMAIN = "DIGNET-SIGN-v1"` and `len16` is the big-endian `u16` byte length of
  `payload_type` (rejected when `payload_type` exceeds `u16::MAX` bytes).

The distinct domain tags close the cross-protocol signing oracle: a signature minted for one purpose
can NEVER validate as the other.

**Handshake (engine's view).**

1. `begin { profile_did, signing_pubkey_hex }` → the engine validates the DID + 48-byte hex key, mints
   a random nonce + `session_candidate`, and remembers the pending `{ nonce, profile_did,
   presented_pubkey }`. Returns `{ nonce_b64, session_candidate }`.
2. `attach { session_candidate, signature_b64, profile }` → the engine consumes the candidate (one
   nonce, one attempt), then: resolves the DID's on-record slot-`0x0010` key via a
   `DidSigningKeyResolver`; **REQUIRES** the resolved key to equal the presented key; BLS12-381 G2 AugScheme-verifies
   the challenge signature against it; only then opens an in-memory session. Returns `{ session_id,
   engine_capabilities }` (`["content.serve", "content.fetch", "sync", "subscribe"]` — keyless by
   construction; the app MUST tolerate capabilities it does not recognize).
3. `detach { session_id }` → drops the in-memory session.

**Custody invariants (HARD RULE).**

- The engine only ever VERIFIES signatures; it never holds or derives a user key (VERIFY-ONLY).
- Attach binds to the key the engine RESOLVED for the DID, not merely the key the caller presented — a
  substituted key is rejected (`KeyMismatch`).
- A DID the resolver cannot resolve FAILS CLOSED (`UnknownDid`): no session opens. An "echo"
  resolver that returned the presented key is FORBIDDEN — it would let any caller attach as any DID.
- The attach candidate is consumed whether or not attach succeeds, so a nonce cannot be replayed.

**Bounds.** `MAX_FRAME_BYTES` (1 MiB) and `MAX_INTERLEAVED_CALLBACKS` (64) are the contracts the
(follow-up) transport MUST enforce. The registry itself bounds `MAX_PENDING_CANDIDATES` (256)
begun-but-not-attached handshakes: once at capacity, the OLDEST outstanding candidate is EVICTED so a
flood of never-attached `begin`s cannot grow engine state without bound.

---

## 8. CLI contract

### 8.1. Subcommands

`run` (default when no subcommand; serves in the foreground and is the unix-service entrypoint) ·
`run-service` (hidden; the Windows SCM entrypoint, §9.4; behaves as `run` off Windows) ·
`install` · `uninstall` · `start` · `stop` (each accepting `--scope <auto|system|user>`, §9.1) ·
`status` · `pair` (§7.11) · `open` (§8.5) ·
the **control-parity** subcommands `info` · `config` · `cache` · `stores` · `sync` · `updater` ·
`subscriptions` (§8.6) · `peers` (§8.7) · `network-info` (§8.8) · `logs` (§11).

The `dign` alias binary (§2.1a) exposes this SAME subcommand set with the SAME semantics — `dign
<subcommand>` is equivalent to `dig-node <subcommand>` in every respect except the reported program
name.

### 8.8. `network-info` — this node's own network posture (#303)

`network-info` prints this node's `peer_id`, network id, effective L2 genesis, listen address,
reachability, and its advertised candidate addresses in the node's own advertisement order, which
is IPv6-first (§5.2). The order MUST be passed through untouched: re-sorting would hide a node
whose IPv6 advertisement is missing, which is the fault an operator runs the command to find. An
absent field MUST render as `unknown` and MUST NOT be filled with a plausible default — a
fabricated `direct` or an invented `0.0.0.0` reads exactly like a measurement.

**It reads the OPEN surface and is NOT token-gated, deliberately.** It is the one documented
exception to §8.6's rule that a CLI subcommand presents the master control token: it calls
`dig.getNetworkInfo`, whose body this node already hands any peer that dials it, so a loopback
caller learns nothing a stranger does not. Gating it would buy no confidentiality while costing
real availability — on a `.deb` install the control token is `0600 root:root` (§7.11/#501), so an
ordinary user asking "what is my node's address" would be told to elevate for a read the network
performs for free. This is a property to PRESERVE, not an oversight to tighten later.

### 8.6. Control-parity subcommands (#426)

For EVERY gated `control.*` method the DIG Chrome extension drives (§7), the CLI exposes an
equivalent subcommand, so an operator/agent can drive the node from a terminal exactly as the
extension drives it from a browser. Each subcommand is a THIN dispatch — it calls the SAME
`control.*` method over the node's loopback endpoint, presenting the MASTER control token
(`X-Dig-Control-Token`, read WITHOUT minting — §7.11/#501); no CLI logic is forked from the control
plane. A mutating CLI control is therefore gated by the identical capability as the WS surface (the
on-disk master token = local-machine control), never an unauthenticated backdoor. The one
documented exception is `network-info` (§8.8), which reads an OPEN, already-public surface and is
token-free by design; it is not a control-parity subcommand and this rule does not reach it.

- `info` → `control.status` — the rich node status (version, uptime, cache, hosted-store +
  cached-capsule counts, §21 sync availability). DISTINCT from `status` (§8.3), which is an
  unauthenticated `/health` liveness probe; `info` is the token-gated detailed view.
- `config [get]` → `control.config.get`; `config set-upstream <url>` → `control.config.setUpstream`.
- `cache [get]` → `control.cache.get`; `cache set-cap <bytes>` → `control.cache.setCap`;
  `cache clear` → `control.cache.clear`.
- `stores [list]` → `control.hostedStores.list`; `stores pin|unpin|status <store>` →
  `control.hostedStores.pin|unpin|status`.
- `capsule fetch <store> <root>` → `control.capsule.fetch`.
- `sync [status]` → `control.sync.status`; `sync trigger <store>` → `control.sync.trigger`.
- `wallet balance <address> [--asset xch|dig|<64-hex asset id>]` → `control.wallet.balance`;
  `wallet coins <address> [--asset xch|dig|<64-hex asset id>] [--after-coin-id <id>] [--limit <n>]` → `control.wallet.coins`;
  `wallet coin-by-id <coin_id>` → `control.wallet.coinById`;
  `wallet coin-spend <coin_id>` → `control.wallet.coinSpend`;
  `wallet coins-by-parent <parent_coin_id> [--after-coin-id <id>] [--limit <n>]` →
  `control.wallet.coinsByParent`;
  `wallet arrivals [--after-seq <n>] [--limit <n>]` → `control.wallet.arrivals`; `wallet peak` →
  `control.wallet.peak`; `wallet reset-coin-db --confirm` → `control.wallet.resetCoinDb`;
  `wallet broadcast <signed_bundle_hex>` → `control.wallet.broadcast`. The
  open chain reads (everything above except `broadcast` and `arrivals`) need no token; `broadcast` is token-gated like every
  other mutation, and carries only already-signed bytes (§908).
- `wallet export-seed [--path <file>]` reaches NO control method. It is a LOCAL, OFFLINE read of
  this node's encrypted seed file: it decrypts the file under the wallet password supplied on the
  terminal and prints the recovery phrase to stdout. It opens no socket, adds no `control.*` method
  and adds no loopback endpoint, so it grants nothing beyond what local filesystem access plus the
  password already grant. It accepts BOTH on-disk seed formats: the current `dig-keystore` container
  and the legacy `EncryptedSeed` layout (leading version byte `1`) that pre-migration files use.
  `--path` overrides the default location, because a file written by an older build can sit under a
  base directory the current build no longer resolves. `--json` is REFUSED: a recovery phrase must
  not be emitted as machine-readable output. The command exists only to let a user move a
  node-custodied wallet out before node-side user custody is removed, and is deleted with it.
- `updater [status]` → `control.updater.status`; `updater set-channel <ch>` / `pause [--until <s>]`
  / `resume` / `check-now` → the matching `control.updater.*`.
- `subscriptions [list]` → `control.listSubscriptions`; `subscriptions add|remove <store_id>` →
  `control.subscribe`/`control.unsubscribe`.

**Parity is enforced mechanically.** `control::CONTROL_METHODS` is the canonical set of every
`control.*` method the node resolves; a compile-time-adjacent test asserts every method in it is
reachable from a CLI verb, so a new node control method cannot ship without a CLI subcommand. That
test reads a list built from the CLI's own action enum, so it proves an action EXISTS, not that a
command line reaches it; the wallet verbs are additionally pinned by tests whose input is an argv,
which fail unless the parser really accepts the verb and carries its operands through to the wire.

### 8.7. `peers` — view + manage peer connections (#559)

`peers` reaches parity with the extension's peer surface (`src/features/peers/peersApi.ts`):

- `peers [list]` → `control.peerStatus` — the live peer status: running flag, connected count,
  relay reservation, and a **per-peer array** `peers[]`, each element
  `{ peer_id, via, direction }` — plus `address` — where `via ∈ {"direct","relay"}` is the REAL per-peer
  transport (a peer whose gossip rides the relay's RLY-002 forwarder reports `"relay"`, every other
  peer `"direct"`, sourced from dig-gossip's `connected_pool_peers_with_via`) and
  `direction ∈ {"outbound","inbound"}`.
  `address` is OPTIONAL and MUST be present only when the pool reported a dialable destination: an
  element whose only reported remote is not a destination — an unspecified IP (`::` / `0.0.0.0`) or
  port `0`, which is what dig-nat records for a relay-accepted circuit with no configured relay
  endpoint — MUST OMIT the key rather than emit the wildcard. A consumer MUST therefore treat a
  missing `address` as "this peer has no known dialable address", never as a malformed element.
  The peer-facing `dig.getPeers` carries the SAME rule in the shape its own wire uses: each peer
  row's `addresses` is an ARRAY, so a peer with no dialable destination MUST be emitted with an
  EMPTY array — the row kept, the address withheld. The row MUST NOT be dropped (the asking node
  would not learn the peer exists, and it may still be reachable via the relay), and the key MUST
  NOT be omitted or set to null (`dig.announce` validates that `addresses` IS an array). A node
  MUST NOT serve a non-destination to a remote peer as a dial candidate: a peer that dials it
  wastes one of its few dial slots, and a peer that caches it caches a hole.
  The array is present whenever a peer network is running and
  omitted (count only) on the in-process FFI path / before bring-up. The per-peer `peer_id` is the
  machine-checkable proof of a mutual A↔B connection (each side lists the other's `peer_id`). Peer
  addresses are displayed **IPv6-first, IPv4 second** per the ecosystem §5.2 address-family policy.
- `peers connect <peer>` → `control.peers.connect` — dial a peer via the live gossip pool. `peer` is
  EITHER a dialable socket address (`host:port`, IPv6 in brackets) dialed over the full NAT ladder, OR
  a `peer_id` (64-hex) honoured only if already connected (idempotent). Returns
  `{ connected: true, peer_id }`; a bare unknown `peer_id`, a malformed argument, a dial failure, or no
  running peer network each return a deterministic control error. CONTROL-plane — reachable only from
  the loopback admin / in-process dispatch, NEVER over the mTLS peer surface.
- `peers disconnect <peer>` → `control.peers.disconnect` — drop a pooled peer, closing its mTLS link
  (the inverse of `connect`). `peer` is a `peer_id` (64-hex); the pool then replenishes toward target.
  Returns `{ disconnected: true, peer_id }`. Idempotent — disconnecting a `peer_id` that is not (or no
  longer) connected succeeds as a no-op. A malformed `peer_id` or no running peer network returns a
  deterministic control error. CONTROL-plane — loopback admin / in-process dispatch only, NEVER over
  the mTLS peer surface.
- `peers ping <peer> [--peer-id <64hex>]` → `control.peers.ping` — test EVERY rung of the connection
  ladder against a peer and report which one reached it (§7.4a). `peer` is a 64-hex `peer_id` or a
  dialable address; `--peer-id` pins the identity the certificate must derive, which is required for
  an address the node cannot already name an identity for. The human output leads with an
  `[OK]`/`[WARN]`/`[FAIL]` marker matching the graded severity, then one line per rung; `--json`
  emits the §7.4a result verbatim. Read-only and bounded — see §7.4a for the full contract.
- `chia-peers` / `chia-peers list` → `control.chiaPeers.list` — the tracked CHIA full-node peers (a
  different network from `peers`, which is DIG gossip). The human view counts the TRUSTED peers and
  the BANNED ones separately from the total, because the trusted rows are the only ones that can move
  the replica on their own word and the banned rows are the only record of what the node is
  excluding. Each row is labelled `trusted (you added it)`, `discovered (must be corroborated)` or
  `BANNED`, and a peer with no telemetry shows its peak as `unobserved` — never `0`, which would read
  as a trusted peer stalled at genesis. Endpoints are joined by the contract's own helper, so an IPv6
  literal is BRACKETED: `::1` + `8444` renders `[::1]:8444`, never `::1:8444`, which is a different
  valid address. An empty list SAYS so and names the verb that fills it. `--json` emits the result
  verbatim.
- `chia-peers add <ip>` → `control.chiaPeers.add` — TRUST a Chia full node. Requires the MASTER
  control token; a paired controller MUST be refused. The command MUST state the corroboration it
  costs at the moment it is granted: `--help` explains that this node otherwise believes a chain
  answer only once several independently-chosen peers agree, that a peer added here can advance, roll
  back or complete the wallet replica alone, and that the operator should add only **a node they run
  themselves**. The success line repeats the node's own `notice` verbatim and follows the RESULTING
  trust state — adding a BANNED peer un-bans it WITHOUT granting trust, and the line says so rather
  than claiming a bypass nothing conferred. A bare `chia-peers` with no sub-action LISTS rather than
  adds — a default must never be the act that costs something.
- `chia-peers remove <ip> [--ban]` → `control.chiaPeers.remove` — stop trusting a peer. Requires the
  MASTER control token, so a paired controller cannot strip peers the operator deliberately trusts.
  The output MATCHES on `outcome`: `no_such_peer` is reported as having removed NOTHING, naming that
  any peer the operator meant to un-trust is STILL trusted, because reporting it as success would
  leave them believing they revoked custody-grade trust. A real removal distinguishes forgetting from
  banning, because only the latter stops discovery re-adding it.
- `peers ban <peer> --state <ban|blacklist|none>` → `control.peers.setBan`; `peers pool-config
  --max-connections <n>` → `control.peers.setPoolConfig` remain a **known node-side gap**: until the
  node ships those RPCs those verbs surface the node's METHOD_NOT_FOUND. The CLI verbs exist now so the
  surface reaches parity and lights up with NO CLI change once the node implements them.

### 8.5. `open` — the OS scheme handler (#389)

`dig-node open <link>` is the target the installer registers for the OS `chia://` and
`urn:dig:chia:` protocol handlers (`dig-node open "%1"`). It is the OS-level fallback resolver for a
DIG link that no in-browser DIG extension intercepted.

- **Input.** Accepts ONLY `chia://<storeId>[:<root>][/<path>]` and
  `urn:dig:chia:<storeId>[:<root>][/<path>]` (scheme match is case-insensitive). The store reference
  MUST be canonical 64-hex (`storeId` or `storeId:root`).
- **Untrusted-input validation (MUST).** The argument arrives from an OS handler and may be
  attacker-influenced (a hostile page can invoke a registered scheme). The command MUST reject every
  other scheme (`file:`, `javascript:`, `data:`, `http(s):`, …), shell metacharacters, control
  characters, whitespace, and `..` path traversal, and MUST NOT pass the argument to a shell — the
  resolved URL is launched via the OS "open a URL" facility with the URL as a SINGLE, non-shell argv
  entry (Windows `rundll32 url.dll,FileProtocolHandler`, Linux `xdg-open`, macOS `open`). A rejected
  link exits `USAGE` (2) and launches nothing.
- **Resolution (MUST route through the canonical resolver, #745).** `open` is a CLIENT operation, so
  it MUST resolve the link through the shared **`dig-urn-resolver`** — the canonical §5.3 ladder
  (`dig.local` → `localhost:9778` → `rpc.dig.net`) with FAIL-CLOSED integrity verification — exactly
  like every other URN-consuming client (the extension URN bar, the SDK). It MUST NOT hard-roll a
  single `localhost:9778/s/…` URL, and MUST NOT surface a raw upstream error string (e.g. a `502`) to
  the user. The resolver — never this command — decides whether the content is loadable and NEVER
  returns unverified bytes. This dependency lives ONLY in the service shell's open-command path, never
  in the node engine (`dig-node-core`), where it would be a dependency cycle.
- **Behavior on a verified `Success`.** Opens the user's DEFAULT browser at the best
  browser-navigable form, in §5.3 preference order, opening the first tier that actually SERVES the
  content (each cheaply probed):
  1. `http://<storeId>.dig/<path>` — offered ONLY for a rootless link (the host cannot pin a root);
  2. `http://dig.local/s/<storeId>[:<root>]/<path>`;
  3. `http://<host>:<port>/s/<storeId>[:<root>]/<path>` (host/port from config, default `localhost:9778`).
  If NO browser tier can serve the content (e.g. the local `/s/` chain-read is 502-ing) but the
  resolver still returned VERIFIED bytes via `rpc.dig.net`, the command serves those verified bytes
  over an EPHEMERAL LOOPBACK HTTP endpoint (`http://127.0.0.1:<port>/…`) and opens THAT — so the user
  always sees the exact verified content, never a raw error.
- **Resolved bytes MUST NOT be written to disk or OS-opened as a file (SECURITY, #745).** The resolved
  bytes, their content type, and the resource name are ALL attacker-controlled (anyone may publish a
  store), and a verified `Success` proves only chain-inclusion, NOT safety. Writing them to a temp file
  and handing that to the OS default-open would bypass the browser's download protections and let an
  attacker store execute code (e.g. a `.hta`/`.js` written without Mark-of-the-Web → RCE; HTML would
  also gain a privileged `file://` origin). The command MUST therefore serve the bytes over a loopback
  `http://127.0.0.1:<ephemeral>` origin instead (short-lived, `X-Content-Type-Options: nosniff`,
  attacker-influenced header values sanitized of CR/LF), so the browser applies its normal
  render-vs-download / Mark-of-the-Web / origin-sandbox handling.
- **Behavior on a non-success / hard error.** On `IntegrityFailure`, `Unreachable`, or a hard resolve
  error (not-found / rpc error / **root-required** — a ROOTLESS link the untrusted `rpc.dig.net` tier
  refuses to resolve without a chain-anchored root), the command MUST show a BRANDED DIG error asset
  from the resolver (`dig_urn_resolver::images`), served over the same loopback endpoint — NEVER a
  hand-rolled page and never a raw error string. A branded page is shown only for a link that PARSES as
  a valid DIG URN but fails to RESOLVE; a link that fails the untrusted-input validation above still
  exits `USAGE` and shows nothing.
- **The branded asset's served filename MUST be OUTCOME-SPECIFIC** — `dig-error-<outcome>.png` (e.g.
  `dig-error-root_required.png`, `dig-error-unreachable.png`, `dig-error-integrity_failure.png`), never
  a single opaque `dig-error.png` for every outcome — so the opened `http://127.0.0.1:<port>/…` URL
  itself names WHY the open failed. The command MUST also emit a one-line stderr diagnostic naming the
  resolved URN + the outcome that fired, so a failing `open` is diagnosable (it MUST NOT log resolved
  bytes).
- It NEVER opens `chia://` at the OS level (dig-node is itself the OS `chia://` handler, so that would
  recurse) and NEVER opens a dig-node GUI (it has none). Under `--json`:
  `{ opened: true, mode: "browser"|"content"|"error", outcome, url, store_id, root, path }` (`url` is
  always an `http(s)` URL — never a local file path).

### 8.2. `--json` (global flag)

Under `--json` every subcommand MUST emit exactly ONE structured JSON object to **stdout** and
route human prose to **stderr**.

- Success envelope: `{ ok: true, action, service: "dig-node", version, …result-fields }` (result
  fields folded in at top level).
- Error envelope: `{ ok: false, action, error: { code, exit_code, message, hint } }` where `code`
  is the symbolic exit-code name and `exit_code` the numeric code; the process still exits with
  that code.

Without `--json`: success summaries print to stdout; errors print `error: …` (and optional
`hint: …`) to stderr.

### 8.3. `status` semantics

`status` probes `GET /health` on the configured address (blocking HTTP/1.0 probe, 2 s timeouts).
"Serving" means the response **status line** is 2xx (parsed from the status code token — never a
substring match). A refused connection is `serving: false`, not an error. `serving: false` maps to
exit `1` (`NOT_SERVING`) so scripts can gate on liveness; the JSON result carries `serving`,
`addr`, `health_url`.

### 8.4. Exit-code table (stable)

| Exit | Name | Meaning |
|---|---|---|
| 0 | `OK` | Success. |
| 1 | `NOT_SERVING` | `status`: the node is not responding. |
| 2 | `USAGE` | Bad arguments / usage error. |
| 3 | `PERMISSION_DENIED` | Elevation required (Windows `install`/`uninstall`). |
| 4 | `SERVICE_FAILED` | A service-manager operation failed. |
| 5 | `BIND_FAILED` | `run`: could not bind the loopback address. |
| 6 | `IO_ERROR` | Other I/O error. |
| 12 | `NODE_UNREACHABLE` | The node did not answer; the operation was not measured. |

I/O-error mapping, in the order `ExitCode::from_io_error` matches — every arm, because a partial
list reads as complete and the omitted arms are exactly the ones a caller gets wrong:
`PermissionDenied` → 3; `AddrInUse`/`AddrNotAvailable` → 5; `InvalidInput` → 2 (a bad argument
surfaced as an I/O error is still a usage error); `ConnectionRefused` → 12; anything else → 6.

Numeric values and symbolic names are a stable contract and MUST NOT be renumbered.

**The occupied numbers span the whole DIG command line, not this CLI alone (MUST).** `dign` and
dig-app's `diga` deliberately share one numbering so a caller sees one surface across both
(`dig-app-core/src/gateway/outcome.rs`), so a code is available only if it is unoccupied
ECOSYSTEM-WIDE. Absence from the table above does NOT make a number free — this repo has already
paid for that reasoning once in the JSON-RPC error space, where `-32015` was taken as "the next
free code" from the owning crate's own list and collided with a released `METADATA_TOO_LARGE`,
forcing a yank. The full occupied set, measured, is:

| Code | `dign` (this CLI) | `diga` (dig-app gateway) |
|---|---|---|
| 0 | `OK` | `OK` |
| 1 | `NOT_SERVING` | — |
| 2 | `USAGE` | `USAGE` |
| 3 | `PERMISSION_DENIED` | — |
| 4 | `SERVICE_FAILED` | — |
| 5 | `BIND_FAILED` | — |
| 6 | `IO_ERROR` | `IO_ERROR` |
| 7 | — | `NOT_CONNECTED` |
| 8 | — | `ENGINE_ERROR` |
| 9 | — | `LOCKED` |
| 10 | — | `NOT_FOUND` |
| 11 | — | `DENIED` |
| 12 | `NODE_UNREACHABLE` | — |

0–11 were therefore taken before this CLI added a code, and 12 is the first free number. A new
code MUST be drawn from 13 upward and MUST re-check BOTH tables first; 126, 127 and 128+n are
reserved by the shell and MUST NOT be used.

---

## 9. OS-service contract

9.0. **The service MUST always be stoppable (dig_ecosystem#2880).** A running service MUST answer
a service-manager stop request promptly and MUST reach a stopped state, whatever the state of its
internals.

- Raising a stop from the control handler MUST NOT block, MUST NOT fail, and MUST NOT depend on
  any bounded shared resource — in particular NOT on the async runtime's blocking-thread pool,
  which the wallet replica's synchronous database work also draws from. A stop delivered onto a
  saturated pool is accepted and then never acted on, which leaves the service `Running` and
  serving HTTP while the service manager reports `1061`
  (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL`) — a node the user cannot turn off.
- Graceful shutdown MUST be BOUNDED. If the serve body has not wound down within the deadline the
  service MUST report itself stopped anyway, and MUST report that run as failed rather than as a
  clean exit — a forced stop reported as graceful is a false claim about whether shutdown worked.
- Deadline: 20s, inside the Windows SCM's own 30s stop timeout, so the service manager learns the
  outcome from the service rather than inferring a hang.

9.1. **Service scope (`--scope`, #526).** A registration lives in exactly ONE of two scopes, and
`install`, `uninstall`, `start` and `stop` all accept `--scope <auto|system|user>`, default `auto`.

| Scope | Where the registration lands | Runs as | Survives a reboot with NO login session | Requires |
| --- | --- | --- | --- | --- |
| `system` | systemd system unit (`/etc/systemd/system/dignetwork-dig-node.service`, `WantedBy=multi-user.target`) · launchd daemon (`/Library/LaunchDaemons/net.dignetwork.dig-node.plist`, `system` domain) · Windows SCM service | root / LocalSystem | **YES** — starts at boot | root / Administrator |
| `user` | systemd user unit (`~/.config/systemd/user/dignetwork-dig-node.service`) · launchd agent (`gui/<uid>` domain) | the installing user | NO — starts with that user's session | nothing |

- **Resolution (normative).** Given the operator's choice, whether the OS HAS a user scope, and
  whether the process is root, the resolved scope MUST be: `system` whenever the OS has no user
  scope (Windows SCM) — **including for an explicit `--scope user`, which cannot be honoured
  there**; otherwise the explicit `--scope system`/`--scope user` **verbatim** (an explicit choice is
  authoritative and MUST NEVER be silently overridden by the privilege level); otherwise, for
  `auto`, `system` when running as root and `user` when not.
- **`auto` is the default**, so a caller that passes no flag — including a dig-installer release
  predating this flag — gets the historical behaviour: user scope for an unelevated desktop install,
  and now system scope for an ELEVATED install, which is what makes a headless install survive a
  reboot. Root has no `systemd --user`/D-Bus session, so a user-scope registration attempted as root
  cannot succeed at all.
- **A system scope requested without root MUST be refused** (`PERMISSION_DENIED`) with a message
  naming the missing privilege and the `--scope user` alternative — never silently downgraded to
  user scope (a silent downgrade produces a registration that does not survive a reboot, which the
  operator asked to avoid). On Windows, the equivalent up-front check is elevation itself:
  `install`/`uninstall` MUST fail fast with a clear `PERMISSION_DENIED` when the console is not
  elevated (probed up front, not deep inside `sc.exe`).
- **Cross-scope migration (`install`).** Before registering at the resolved scope, `install` clears
  this service label at the OTHER scope, so a host upgrading from a previous user-level install does
  not end up with two registrations both starting a node bound to the same port. TWO mechanisms, with
  different reach, and the difference is normative because the first one CANNOT work as root:
  1. **The OS-manager sweep** asks the current process's own service manager about the other scope.
     It is PROBE-GATED (a scope holding no registration is never written to) and therefore only ever
     sees the CURRENT account: root has no systemd `--user` session, and `gui/<uid>` is uid 0's
     domain, so as root this mechanism sees nothing and does nothing. Reported as
     `result.migrated_from_scope { scope, found, removed, indeterminate, error }`.
  2. **The per-account FILESYSTEM sweep**, which runs when the resolved scope is `System` on a
     user-capable OS, because that is the case mechanism 1 cannot cover. It enumerates real
     registration FILES under the fixed account roots `/home`, `/root` and `/Users` — the systemd
     user unit `<home>/.config/systemd/user/dignetwork-dig-node.service` together with its
     `default.target.wants/` enablement symlink, and the launchd agent
     `<home>/Library/LaunchAgents/net.dignetwork.dig-node.plist` — best-effort STOPS each running
     instance (`launchctl bootout gui/<uid>/<label>`, `systemctl --user --machine=<account>@.host
     stop <unit>`), then unlinks them. Reported per account as
     `result.user_scope_sweep { removed_accounts, failed_accounts, residual }`. Stopping matters as
     much as unlinking: a still-running user-level node holds the node's port, and the `dig-node
     start` an installer treats as fatal would fail with `EADDRINUSE`.
     - **Root deleting inside user-owned directories is symlink-refusing.** No intermediate
       DIRECTORY component of a removal path below the account root may be a symlink (checked with
       `lstat`, which does not follow); if one is, that registration is refused and REPORTED rather
       than removed, because as root a redirected walk would be an arbitrary-delete primitive. The
       FINAL component MAY be a symlink — systemd's `default.target.wants/` enablement entry always
       is, and refusing it would leave the unit ENABLED — because it is only ever unlinked, which
       removes the link and never follows it. Only individual files and symlinks are ever unlinked —
       never a directory tree.
     - **Stated residual (NOT covered).** A user-scope registration under a home directory outside
       `/home`, `/root` or `/Users`, or under a non-default `XDG_CONFIG_HOME`, is not discoverable
       and is NOT removed; that residual is stated in the install output, and the affected user
       removes it with `dig-node uninstall --scope user`.
  Both sweeps are best-effort and a failure in either MUST NOT fail an otherwise-good install — but a
  registration that was seen and could not be removed MUST be reported as a `WARN` in the human
  summary and in `--json`, never silently dropped.
- **The existence probe is ADVISORY; the OS deregistration is AUTHORITATIVE.**
  `launchctl print gui/<uid>/<label>` cannot see a per-user agent from a session with no Aqua/GUI
  domain (a headless CI runner, an ssh login), so it reports absence for a service that IS
  registered. Therefore the scope the operator NAMED (or `auto` resolved to) MUST be deregistered
  **unconditionally**, without gating on the probe — a probe false-negative MUST NEVER turn an
  uninstall into a silent no-op. A scope merely being SWEPT (the other scope during `install`, the
  second scope of `uninstall --scope auto`) MUST be probe-gated, so a scope nobody asked about is
  never written to.
- **`uninstall` scope sweep.** An explicit `--scope` removes exactly that scope. `--scope auto`
  removes the resolved scope and then sweeps the other, so an uninstall does not leave the other
  scope's registration of the CURRENT account behind (the residual above applies here too: another
  account's user-scope registration is that user's own `dig-node uninstall --scope user`). Every
  scope is reported
  (`result.removed_scopes: ["system", "user"]`). Anything short of a complete removal MUST be an
  error naming the scope, never a silent success. A scope is **indeterminate** — unknown, and
  therefore reported as unresolved — when the removal did not succeed AND its failure was not the OS
  positively reporting absence: the classification is by the removal error's KIND, where `NOT_FOUND`
  is the ONLY honest "there was nothing here" signal and anything else (a permission failure on a
  root-owned unit, an unreadable domain, a tool that could not be located in a privileged directory)
  leaves a registration that may still be present. Only when nothing was
  removed anywhere AND nothing is unresolved is the result `NOT_FOUND` ("nothing to uninstall"),
  carrying the underlying removal error as context.
- **The existence probe is THREE-VALUED, and only the OS may say "absent".** The probe answers
  `present`, `absent`, or `unknown` — there is no fourth outcome — and it MUST NOT report `absent`
  for a scope it could not READ. The three answers are decided in a fixed order, and the ORDER is
  normative:

  1. **A probe that SUCCEEDED is `present`**, tested before any absence test. Success outranks the
     stderr entirely: a probe that exits 0 is `present` even if its stderr carries an absence
     phrase (a warning about some other unit) or an absence exit code.
  2. Otherwise, a **positive OS absence signal** (exhaustively enumerated below) is `absent`.
  3. Otherwise the outcome is **`unknown`, carrying the tool's own message** verbatim.

  The absence signals are EXACTLY these, per backend, and a reimplementation MUST recognise every
  one of them — the set is closed, and nothing outside it may become `absent`:

  | Backend (probe) | `absent` iff |
  | --- | --- |
  | systemd (`systemctl [--user] cat <unit>`) | stderr contains `no files found for` **or** `could not be found`. **No exit-code condition** — systemd's exit codes are not a reliable absence signal, so the phrasing alone decides. |
  | launchd (`launchctl print <domain>/<label>`) | exit code `113` **or** stderr contains `could not find service`, `no such process`, or `no such file`. The code and the phrases are INDEPENDENTLY sufficient: either one alone is `absent`. |
  | Windows SCM (`sc query <name>`) | exit code `1060` (`ERROR_SERVICE_DOES_NOT_EXIST`) **only**. No stderr phrasing participates, and no neighbouring code does: `1059`/`1061` are `unknown`, as is `5` (`ERROR_ACCESS_DENIED`). |

  **The stderr match is a CASE-INSENSITIVE SUBSTRING search**, never equality and never a prefix:
  the phrase above must be found anywhere within a case-folded copy of the tool's stderr, because
  the OS embeds it mid-sentence and capitalises it its own way (`No files found for
  dignetwork-dig-node.service.`, `Unit dignetwork-dig-node.service could not be found.`). Matching
  on equality, on a prefix, or case-sensitively would classify a genuinely-absent service as
  `unknown`.

  Every other outcome is `unknown` and carries the tool's own message: `systemctl --user` with no
  reachable bus (its state when run as root), a launchd domain that cannot be bootstrapped from a
  session with no Aqua domain, a permission failure, a signal-terminated probe, or an OS tool that
  could not be located in a privileged directory. `unknown` MUST NOT be collapsed into "not
  registered" ANYWHERE. Concretely: the "is there something here" accessor is false for `unknown`
  exactly as it is for `absent` (it answers only "positively present", so no caller can read a
  `false` as "nothing is registered"), and the accessor that demands certainty — used by the
  clean-reinstall and the post-delete removal wait — MUST return an ERROR on `unknown` rather than
  either boolean. It makes a swept scope **indeterminate** (above), and where a caller cannot
  proceed without certainty — the clean-reinstall, and confirming a deletion took effect — it is an
  ERROR, never a `false` that would create over a registration that may be live. This state is
  therefore reachable from the real OS backend, not only from a test double.
- **Native packages register system scope**, consistently with `--scope system`: the `.deb`'s static
  systemd unit is `WantedBy=multi-user.target` running as root, and the macOS `postinstall`
  bootstraps into the `system` launchd domain (§9.7).

9.1a. **Privileged execution hygiene (HARD RULES).** Every service verb now resolves the scope from
the process's privilege level, so all of the following execute while root during the prescribed
`sudo dig-node install --scope system`:

- **The effective uid MUST come from `geteuid()`**, never from a spawned `id`. A bare program name is
  resolved through `$PATH`, and `/usr/local/bin` — group-writable `root:staff 2775` on Debian/Ubuntu
  and user-owned under Intel Homebrew — leads sudo's default `secure_path`, while macOS sets no
  `secure_path` at all. A planted `id` would therefore run AS ROOT; and one printing a non-zero uid
  would additionally resolve the scope to `user`, which is exempt from the privileged-target gate
  (§9.2c) — one writable `PATH` entry would switch that gate OFF.
- **Every OS tool MUST be executed from an ABSOLUTE path resolved out of a fixed list of privileged
  directories** (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; `%SystemRoot%\System32` and
  `%SystemRoot%` on Windows). `/usr/local/bin` MUST NOT appear in that list. A tool that cannot be
  found in it MUST NOT be run at all (fail closed), and the failure is reported.
- **The process `PATH` MUST be pinned to that same list, and `WINSW_PATH` removed, for the duration of
  a service verb.** Unix resolves a bare name with `execvp` against the CALLING process's `PATH`, so
  this is the only place spawns made by DEPENDENCIES can be constrained — and the service-manager
  library selects a **WinSW** backend whenever a `winsw.exe` is on `$PATH` or `%WINSW_PATH%` names an
  existing file, then executes it as the elevated installer, which would hand an attacker the entire
  service definition.
- **No baked service-environment key or value may contain a control character** (newline,
  carriage return or NUL)
  when the resolved scope is `System`. Each entry is written verbatim as one `Environment="K=V"` line
  of a root-owned systemd unit file, so a line terminator appends further DIRECTIVES that run as root
  (`ExecStartPre=` may appear repeatedly and runs before `ExecStart`). The refusal names the offending
  key and is stated over the CLASS of control characters, not over any particular directive. Such a
  value is also rejected at its SOURCE (`normalize_upstream`, `control.config.setUpstream`) so it
  cannot persist in `config.json` and be baked by a later install. User scope is exempt: that unit is
  written by, and runs as, the user who already controls the values.

9.2. **Recorded environment.** `install` MUST register the absolute path of the currently-running
executable (never a PATH lookup) and record the resolved config as service environment variables:
`DIG_NODE_PORT`, `DIG_NODE_HOST`, `DIG_RPC_UPSTREAM`, and — **only when explicitly
configured** — `DIG_NODE_CACHE` (omitting it preserves the shared-cache default, §3.5). The
service is registered with `autostart: true`.

9.2a. **Restart-on-crash recovery (all 3 platforms).** A crashed `dig-node` service MUST come back
up on its own, not sit stopped until a human restarts it:
  - **Linux (systemd)** and **macOS (launchd)** get this from `service-manager`'s own install
    defaults with no extra step — systemd's generated unit sets `Restart=on-failure`; launchd's
    generated plist sets `KeepAlive: true` (alongside `RunAtLoad: true` from `autostart`).
  - **Windows (SCM)** has no such default: `sc create` alone leaves recovery actions at "Take No
    Action". `install` MUST additionally configure them after a successful `mgr.install`, by
    invoking `sc.exe failure <SERVICE_LABEL> reset= 86400 actions=
    restart/5000/restart/10000/restart/30000` (reset the failure counter after 1 day with no
    further crashes; restart after 5s/10s/30s on the 1st/2nd/subsequent failure in that window) —
    `<SERVICE_LABEL>` here is `net.dignetwork.dig-node` used literally (§2.4's `to_qualified_name`
    rejoins its 3 segments unchanged, so it is the exact registered SCM service name). This step is
    **best-effort**: a failure to configure recovery actions MUST NOT fail the whole `install` (the
    service is still registered and usable) — it surfaces as a `note` in the human summary and
    `result.recovery_configured: false` in `--json` output (`true` otherwise, and always `true` on
    Linux/macOS since their defaults already apply).

9.2b. **Display name + clean-reinstall (`install`, #494).** `install` is a stop→delete→wait→create
CLEAN-REINSTALL, never a reconfigure-in-place, so re-running it against an already-registered
service does not hit Windows `CreateService` error 1073 ("the specified service already exists"):

- If the service is not yet registered, `install` simply creates it.
- If it IS already registered, `install` best-effort stops it, deletes (deregisters) it, polls for
  the deregistration to actually take effect (bounded, `TimedOut` if it never does — a lingering
  Windows deletion can hold on until open handles close), and only THEN recreates it.
- **`install` never starts the service** (fresh or reinstalled) — it only registers
  `autostart: true` for the next boot/login. A caller starts it explicitly with `dig-node start`.
  This is deliberate: the dig-installer calls `install` then, when configured to start it, a
  SEPARATE `start` and treats a `start` failure as fatal for that step; if `install` also started
  the service, that second `start` would hit "already running" and could flip the installer's
  reported outcome to failed even though the service is up.
- **Windows display name.** `sc create` (via `service-manager`) always sets the SCM display name to
  the service id; `install` follows it with `sc config <id> displayname= "DIG NETWORK: NODE"`, then
  reads the config back with `sc qc <id>` to CONFIRM the override took (rather than trusting the
  `sc config` exit code alone). Both steps are best-effort — a failure leaves the service
  registered and usable, just possibly showing its id instead of the friendly name in the Services
  console; `result.display_name_verified` (`--json`) reports whether the read-back confirmed it.
- **macOS/Linux friendly name.** launchd has no display-name-equivalent plist key, so the daemon is
  identified by its `Label` (`net.dignetwork.dig-node`) only. systemd's `Description=` DOES carry a
  friendly name; the native `.deb`'s STATIC unit file (§9.7) already sets
  `Description=DIG NETWORK: NODE`. A bare `dig-node install` (not via the `.deb`) registers a
  service-manager-generated unit whose `Description` is the service id, matching `dig-dns`'s own
  established precedent for the CLI-only path.

9.2c. **Privileged-target gate (`install`, #565 LPE).** A **system-level** registration (Windows
SCM, always LocalSystem; a root systemd/launchd daemon) records the currently-running binary as its
`ExecStart` / SCM `binPath` / launchd `ProgramArguments` (§9.2). If that binary sits in a
user-writable directory, a non-privileged local user could replace it and gain persistent
SYSTEM/root code execution on the next service start — a privilege-escalation vector. So before
registering a system-level service, `install` MUST verify the program's directory is
**privileged-owned across its whole path** (§ the shared whole-path owner check — every ancestor
component privileged-owned, non-reparse) and **refuse with `PERMISSION_DENIED`** otherwise, before any
side effect (no state-dir harden, no service create). This is the SAME spawn-free owner gate the
self-heal spawn root (§7 #565) and the TLS material root (§4.1a #661) use — one shared check,
fail-closed on an indeterminate owner. The refusal MUST NAME the offending path
LEVEL (the first ancestor that fails the check), not merely the program path: the check walks the
whole chain, so a privileged-owned leaf under a user-writable parent is refused, and an operator
cannot act on a refusal that does not say which level failed. A **user-scope** install runs as the
very user who owns the binary, crosses no privilege boundary, and is always allowed. The canonical
install paths (native OS package, §9.7; the dig-installer's root-owned `/opt/dig/bin`) place the
binary in a protected admin-owned location (`%ProgramFiles%\DIG\bin\`, `/usr/…`), so
they satisfy the gate; a manual system-scope `dig-node install` from a user-writable download
directory is what the gate refuses — and it is refused loudly, never downgraded to user scope. **The program FILE itself MUST also clear the bar** — owned by root/SYSTEM, no group/other write
bit, not a symlink/reparse point — and not merely sit inside a privileged directory: directory
permissions prevent unlink/rename of the entry, but a binary whose OWN mode permits it can be
rewritten in place, and the daemon would execute the new contents at next boot. The two checks are
independent and both required; the refusal names which one failed.

A single explicit, **default-off** opt-out — the `DIG_NODE_ALLOW_INSECURE_SERVICE_TARGET`
env var (truthy `1`/`true`/`yes`) — bypasses the gate with a loud warning, intended ONLY for a
controlled test/dev install of an unreleased build from a build directory (e.g. the `service-smoke`
CI); it MUST NOT be set on an end-user machine. **It is INERT when the resolved scope is `System` and
the process is genuinely root**: that combination is a root boot daemon on a real machine, the env var
is inheritable (`sudo -E`, an export in a root profile, a CI value leaking into an operator shell),
and no inherited variable may disable this gate for it.

9.3. **Entrypoint per platform.** The installed service runs `dig-node run-service` on Windows and
`dig-node run` on systemd/launchd (which exec the foreground process directly).

9.4. **Windows SCM protocol.** `run-service` MUST connect to the SCM via
`StartServiceCtrlDispatcher` under the exact §2.4 label, register a control handler, report
`Running` (accepting `Stop`) promptly — otherwise the SCM kills the process with error 1053 —
serve until the SCM `Stop` control, drive the same graceful shutdown as a signal, and finally
report `Stopped` (Win32 exit 0 on success, 1 on error).

9.4a. **`start` is IDEMPOTENT (#772).** `dig-node start` requests the OS service manager start the
registered service and reports SUCCESS (exit 0) when the service is EITHER freshly started OR
ALREADY RUNNING — a running node is the desired end state, never an error. It MUST recognise the
per-OS already-running signal, which surfaces only in the service manager's output: Windows SCM
error **1056** ("An instance of the service is already running"), launchd "already loaded" /
"already in progress", systemd "already active" (systemd `start` of an active unit is normally a
silent no-op). `--json` reports `already_running: true|false` to distinguish the two success cases.
Any OTHER start failure (e.g. the service is not registered) MUST still surface as an error. This is
what lets the dig-installer call `install` then a separate `start` (§9.2b) without a spurious
failure when the service is already up.

9.5. **Graceful shutdown.** In the foreground, the serve loop MUST stop gracefully on Ctrl-C (all
platforms) or SIGTERM (unix — how systemd/launchd stop the service). One shutdown event MUST fan
out to both listeners (§4.1).

9.6. **Uninstall.** `uninstall` performs a best-effort `stop` first, then removes the registration.

### 9.7. Native install packages (#503)

The canonical end-user install path is a NATIVE OS PACKAGE built by this repo's CI (`package.yml`),
published as GitHub Release assets on each `vX.Y.Z` tag. `dig-updater` fetches + runs the right
package on every update; on Windows `dig-installer` currently places a raw binary instead of running
the `.msi` (unifying that is planned, and until it lands the `.msi` MUST tolerate a foreign binary
already present in the install root — see the Windows entry below). Each package installs the binary,
registers the OS service, registers the `chia://` scheme handler (→ `dig-node open`, §8.5), creates
the machine-wide state dir (§7.3a), and sets the `dig.local` → `127.0.0.2` hosts entry (via the
idempotent, no-shell `dig-node ensure-hosts`, §8.1). The `dig-node install`/`uninstall` CLI (§9.1)
remains for manual/dev use.

- **Windows `.msi`** (WiX; `dig-node-<ver>-windows-x64.msi`). **`dig-updater` runs this package on
  every Windows update** (`msiexec /i <pkg> /qn /norestart`; dig-node's Windows `InstallMethod` is
  `WindowsMsi`), so it is load-bearing for auto-update. `dig-installer` does NOT currently run it —
  it places a raw binary in the install root itself.

  Installs `dig-node.exe` under `%ProgramFiles%\DIG\bin\` — the CANONICAL protected install root.
  That root is MANDATORY for two independent reasons:

  1. **Auto-update convergence.** `dig-updater` reads the installed version from
     `<install-root>\dig-node.exe` after running the package. If the package installs anywhere else,
     the probe reads a file the install never wrote: the probed version never changes, every beacon
     cycle re-runs the same install, and the host never advances — a non-convergent update loop, not
     a cosmetic path difference.
  2. **The installer's own audit.** `dig-installer` verifies the registered service image and the
     fresh-session PATH resolution of `dig-node.exe` against that root, so a package installing
     elsewhere makes every install fail a check against its own payload.

  `ServiceInstall`+`ServiceControl` register
  `net.dignetwork.dig-node` (DisplayName **"DIG NETWORK: NODE"**) running `dig-node.exe run-service`
  as LocalSystem, auto-start, STARTED on install, STOPPED+REMOVED on uninstall; creates
  `C:\ProgramData\DigNode` with a **restrictive DACL — inheritance broken, only SYSTEM +
  Administrators (never Users)** so the token is not world-readable (§7.3a; dig-node leaves a
  pre-existing dir's ACL intact); registers `chia://` under `HKLM\Software\Classes\chia`
  (`shell\open\command` = `"…\dig-node.exe" open "%1"`); MUST NOT modify the machine `PATH` (the
  install root's PATH entry has exactly ONE owner, `dig-installer`, which writes it in the USER hive
  — a machine-hive entry from this package precedes it in a fresh session and shadows it);
  runs `dig-node ensure-hosts` as a deferred (SYSTEM) custom action. A stable `UpgradeCode` +
  `MajorUpgrade` give clean in-place upgrades.

  **Upgrade sequencing (normative).** `MajorUpgrade` MUST schedule `RemoveExistingProducts` BEFORE
  the new files install (`afterInstallValidate`). The previous product's binary, machine-`PATH` row
  and `net.dignetwork.dig-node` registration are then removed, and the service reinstalled and
  started, inside ONE transaction: an interrupted upgrade rolls back to the previous product with
  its service intact, and a completed upgrade ends with the service registered against the new
  image. No reachable resting state has a registered product and no service. Scheduling the removal
  LATER is forbidden: the previous product's `ServiceControl Remove="uninstall"` matches the service
  by NAME and would delete the service the new product had just registered. `REINSTALLMODE=amus`
  MUST NOT be used to force file replacement: it turns a repair into a silent downgrade.

  The package MUST also remove any pre-existing `dig-node.exe` in the shared root before installing
  its own (`RemoveFile`, on install). The root is shared and this package is not its only writer —
  `dig-installer` drops a raw `dig-node.exe` there — and Windows Installer's file-versioning rules
  KEEP such a foreign, unversioned-looking file rather than overwrite it. Without the removal the
  package completes over a binary it did not install, and the version `dig-updater` probes next is
  the stale file's. The removal MUST be scoped to that one file by name: the root also holds
  `digstore`, `dig-dns`, `dig-updater` and `dig-app`.

  All four requirements above — root, no machine `PATH` row, removal schedule, and the scoped
  `RemoveFile` — are asserted by `scripts/tests/msi-install-root.test.sh`.
- **macOS `.pkg`** (`dig-node-<ver>-macos.pkg`, universal arm64+x86_64). Installs `dig-node` to
  `/usr/local/bin`; a LaunchDaemon `/Library/LaunchDaemons/net.dignetwork.dig-node.plist`
  (`RunAtLoad`+`KeepAlive`, `run` with `DIG_NODE_RUN_CONTEXT=service`); a tiny AppleScript app
  (`/Applications/DIG Network.app`, `CFBundleURLTypes` for the `chia` scheme) forwards URL opens to
  `dig-node open`; `postinstall` creates the restrictive state dir, `launchctl bootstrap`s the
  daemon, and registers the handler with LaunchServices.
- **Ubuntu `.deb`** (`dig-node_<ver>_amd64.deb`; `Package: dig-node`, `Depends: libc6`). Installs
  `/usr/bin/dig-node` **and `/usr/bin/dign`**, the latter a relative symlink to the former — the CLI
  is documented ecosystem-wide as `dign`, so a package providing only `dig-node` makes every
  documented command `command not found`. It is a symlink rather than a second copy because both
  binaries are one-line shims over the same entrypoint and clap derives the displayed program name
  from arg0, so the two cannot diverge. Nothing is installed at `/usr/bin/dig`, which belongs to
  BIND's `dnsutils`. Also installed: a systemd system unit `net.dignetwork.dig-node.service`
  (auto-start, `Restart=on-failure`, `DIG_NODE_RUN_CONTEXT=service`, reading
  `EnvironmentFile=-/etc/dig-node/dig-node.env`); the operator-owned conffile
  `/etc/dig-node/dig-node.env` (fully commented out, so an untouched file changes nothing); a
  `.desktop` with `MimeType=x-scheme-handler/chia` registered as the system default handler;
  `postinst` creates `/var/lib/dig-node` (root-owned `0700`), the hosts entry, and enables+starts
  the unit; `prerm` stops+disables it.
- **Configure before joining.** If `/etc/dig-node/no-autostart` exists when the package is
  configured, `postinst` registers the unit (`daemon-reload`) and prints how to start it, but does
  **not** enable or start it — so an operator standing up an isolated network installs without the
  node first joining the public one, minting an identity, and leaving a provider record whose TTL
  outlives the window. The marker is read, never written, by the package: an operator creates it
  before installing and removes it when ready. An install with no marker is unchanged and still
  starts the node, because a node with no configuration MUST still find peers.
  The isolation knobs go in `/etc/dig-node/dig-node.env` and are written `off` rather than empty
  (§ Environment): both spell "none", but an empty assignment does not survive every tool that
  carries it, and a variable that arrives unset falls back to the public compiled-in anchor.
  `scripts/tests/deb-contents.test.sh` builds a package and EXECUTES its `postinst` against a
  recording `systemctl` to assert both the marker path and the unchanged default. The filename + control metadata are **apt-correct + stable** so apt.dig.net
  ingests the Release asset to build its signed apt repo (the repo is GPG-signed by apt.dig.net; the
  `.deb` itself needs no code-signing cert).
- **Scheme registration scope.** All three register the DIG-specific **`chia://`** scheme. The
  `urn:dig:chia:` textual form is accepted by `dig-node open` (§8.5) but is NOT registered as a
  global OS handler — doing so would hijack the entire `urn:` scheme (every URN on the machine).
- **Unix service identity.** The systemd/launchd services run as **root**, so `/var/lib/dig-node`
  and `/Library/Application Support/DigNode` are root-owned `0700` and a non-root operator drives
  control with `sudo dig-node pair` (the remedy the CLI prints, §7.3a).

---

## 10. Error-code catalogue (JSON-RPC wire)

Stable contract: numeric codes, symbolic names, and origins MUST NOT be renumbered or repurposed;
additions are allowed. This catalogue is the canonical set from **`dig-rpc-protocol`** (§1.4) — it
MUST match that crate exactly. `origin` distinguishes who minted the error: `shell` (this service),
`node` (the node library), `upstream` (relayed from the upstream DIG RPC), `boundary` (the
method-not-found cue).

**Canonical control-code assignment.** The control-plane errors are `-32030`/`-32031`/`-32032`/`-32033`.
`-32020`/`-32021`/`-32022` are RESERVED for onion-routing errors (`onion_circuit_unavailable` /
`privacy_requires_local_node` / `onion_hops_out_of_range`) — the published normative contract on
docs.dig.net — and MUST NOT be used for control. (`dig-rpc-protocol` is the source of this resolution;
any client that branched on the old control numbers keys on the symbolic `data.code`, not the
number.) The wallet-read errors occupy `-3204x` (`WALLET_NO_CHAIN_SOURCE` / `WALLET_NOT_SYNCED` /
`WALLET_READ_FAILED` / `WALLET_RATE_LIMITED`); `-3205x` is owned by the chat plane (§ chat) and MUST
NOT collide; `-3206x` is owned by the peer plane (`PEER_PING_REFUSED`). The ingress bound on the
OPEN control reads is `-32033` (`CONTROL_INGRESS_LIMITED`) and sits in the control range rather
than `-3204x` BECAUSE it is not a wallet fact: it is refused by the control server before any
method runs, and it MUST NOT be conflated with the wallet's own `-32043` egress bound.

| Code | Name | Origin | Meaning |
|---|---|---|---|
| -32700 | `PARSE_ERROR` | shell | Request body was not valid JSON. |
| -32600 | `INVALID_REQUEST` | shell | Not a single JSON-RPC object (batch arrays unsupported); also the 421 Host-rejection body. |
| -32601 | `METHOD_NOT_FOUND` | boundary | Not resolved locally or by the upstream (internally: the passthrough cue). |
| -32602 | `INVALID_PARAMS` | node | Invalid/missing method parameters (also minted by the control plane for bad control params). |
| -32000 | `DISPATCH_FAILED` | shell | The shell failed to dispatch the request to the read path. |
| -32004 | `RESOURCE_UNAVAILABLE` | node | Genuine content miss at the requested root; distinct from transport failure. Minted by the node library for a LOCAL miss — `dig.fetchRange` ("resource not held") and `dig.getManifest` ("capsule not held locally") — and relayed with `origin: upstream` when a passthrough upstream returns it. Never a fabricated result. |
| -32005 | `ROOT_NOT_ANCHORED` | node | The node's mandatory read-path anchored-root pin (§14.4) fails closed: the requested root does not match the chain-anchored tip, the store has no confirmed on-chain generation, the chain is unreachable, or a rootless request cannot be resolved under enforcement. Minted by the node library on `dig.getContent`. |
| -32008 | `CONTENT_REDIRECT` | node | The node does not (or, under §17's throttle, will not right now) serve the requested content itself, but the DHT located peer(s) that hold it — `error.data.redirect` names them (`content`, `providers[].peer_id`/`addresses`, `redirect_depth`, `max_redirects`) so the caller re-requests there. The candidate set is CAPPED at `MAX_REDIRECT_PROVIDERS` (= dig-dht's `MAX_ADDRESSES_PER_RECORD`): a redirect NAMES holders (the requestor dials them over its own §5.2 reachability ladder — this node does NOT dial/probe them), so a few candidates suffice and probing-on-miss would itself be an amplification vector. Minted on a content miss (`dig.getContent`/`dig.fetchRange`/the peer range-stream) and on outgoing-bandwidth saturation (§17), bounded by the same redirect-hop cap either way. |
| -32003 | `CONTENT_MISS_RATE_LIMITED` | node | The requested content is not held, and the miss → DHT-lookup path is being driven too fast BY THIS REQUESTOR (§10.4). Minted instead of a redirect/fetch when the per-requestor token-bucket budget is exhausted, so an abusive caller backs off while a DIFFERENT requestor (its own bucket) is unaffected. A well-formed JSON-RPC error, never a silent empty success. Matches `dig_rpc_protocol::ErrorCode::ContentMissRateLimited` (`-32003`, canonical since dig-rpc-protocol 0.7). |
| -32009 | `RANGE_METADATA_UNREPRESENTABLE` | node | A holder cannot frame a conforming range stream for this resource (an inclusion proof over `MAX_INCLUSION_PROOF_B64` is the real case): the resource's own range metadata cannot fit a conforming frame, so this holder can NEVER serve the range. Named explicitly on the peer range-stream serve instead of truncating the stream with a bare `Err`. Matches `dig_rpc_protocol::ErrorCode::RangeMetadataUnrepresentable` (`-32009`). |
| -32010 | `UPSTREAM_ERROR` | shell | The blind-passthrough relay failed (unreachable / non-JSON). |
| -32015 | `METADATA_TOO_LARGE` | node | `dig.getMetadata` refused: the publisher metadata section is too large or too complex to render safely. Refused when the ENCODED section exceeds `METADATA_SECTION_MAX_BYTES` (3 MiB) or its `custom` exceeds `MAX_CUSTOM_ENTRIES`/`MAX_CUSTOM_JSON_DEPTH`/`MAX_CUSTOM_JSON_ELEMENTS` (both checked BEFORE decode, #2160), or the RENDERED body exceeds `METADATA_RESPONSE_MAX_BYTES` (3 MiB, #2145). This section is rendered WHOLE — it cannot be windowed like `dig.getCapsule` — and `custom`/`links` are publisher-controlled, so an oversized/hostile capsule is refused with this bounded error rather than expanded ~16× in memory or blasted into a ~100 MB response (§5.5.1). A normal (kilobyte) metadata section is served unchanged. |
| -32017 | `CONTENT_MISS_INCONCLUSIVE` | peer | No holder was named AND the search could not establish that there is none: a consulted leg timed out, was unreachable, or refused uninformatively (§10.4.5). The OPPOSITE instruction to a plain not-found — a not-found says stop looking, this says the question was not answered and the request MAY be retried. Collapsing the two let ONE slow peer manufacture an authoritative absence and, since a hop relays its answer, propagate it downwards. DEFINED by `dig-rpc-protocol` as `ErrorCode::ContentMissInconclusive` with origin `Peer` — the failure arises in the discovery layer from an unconsultable hop, mirroring `PeerUnreachable`. dig-node adopts the variant and does not assign the number. |
| -32017 | `ContentMissInconclusive` | — | Availability not ESTABLISHED. Also the answer a hop gives while it is still RELAYING a capsule on the requestor's behalf, in which case `error.data.relay_staged_bytes` carries the hop's staged byte count (§21.1). The field is ADDITIVE: a reader that ignores it sees an ordinary inconclusive miss and retries. |
| -32020 | *(reserved: onion `onion_circuit_unavailable`)* | — | Reserved for the onion-routing contract; NOT minted by the control plane. |
| -32021 | *(reserved: onion `privacy_requires_local_node`)* | — | Reserved for the onion-routing contract. |
| -32022 | *(reserved: onion `onion_hops_out_of_range`)* | — | Reserved for the onion-routing contract. |
| -32030 | `UNAUTHORIZED` | shell | `control.*` called without a valid local control token. |
| -32031 | `NOT_SUPPORTED` | shell | A control operation this build/pin cannot perform (e.g. §21 sync without an identity). |
| -32032 | `CONTROL_ERROR` | shell | A control operation failed at runtime (distinct from bad input / absent capability). |
| -32033 | `CONTROL_INGRESS_LIMITED` | shell | An OPEN, token-less `control.*` read was refused AT INGRESS, before the request reached the dispatcher and before any DB work was done for it: this SOURCE's request bound is exhausted. The open reads present no credential, so without this bound an unauthenticated caller can drive unbounded SQLite work (`.coinById`/`.coinSpend` each run up to two lookups plus an LRU `UPDATE`) simply by asking repeatedly. The bound is PER SOURCE — one flooding source MUST NOT refuse another — and the node's OWN loopback operator is EXEMPT, so this code is only ever seen by a non-loopback caller (i.e. under `DIG_NODE_ALLOW_REMOTE=1`). It MUST stay DISTINCT from `-32043 WALLET_RATE_LIMITED`: that bound is on chain EGRESS and protects the third-party oracle, this one is on REQUESTS and protects this process. They fire for different reasons and have different remedies, so collapsing them would leave a caller unable to tell which bound it hit. Back off and retry. |
| -32040 | `WALLET_NO_CHAIN_SOURCE` | node | a wallet chain read (`control.wallet.balance`/`.coins`/`.coinById`/`.coinSpend`/`.coinsByParent`/`.peak`) or `control.wallet.broadcast` had NO live chain source able to answer an arbitrary (non-wallet) address. Distinct from a truthful `0`. A read the node can answer WITHOUT a chain source MUST NOT be refused with this code: the replica fast path and the node own chain-read cache both answer from bytes already in hand, so on `.coinById`/`.coinSpend` liveness is consulted only on a cache MISS. Refusing a cached answer because a third party is momentarily unreachable gives availability away for nothing on exactly the rows a lineage walk re-reads (a spent coin record is immutable), and the refusal then cascades into the retries that exhaust the `-32043` bound. The refusal MUST stay for a miss, and `.coinSpend` MUST treat a PARTIAL cache hit (spend cached, coin record not) as a miss, because the heights come from the record. |
| -32041 | `WALLET_NOT_SYNCED` | node | `control.wallet.balance` of the wallet's OWN address while the local DB is still syncing and no live fallback is attached (nothing can answer yet). |
| -32042 | `WALLET_READ_FAILED` | node | `control.wallet.balance`/`.coins`/`.coinById`/`.coinSpend`/`.coinsByParent`/`.peak` failed at the underlying DB / chain-source layer. On `.coinById` this INCLUDES a chain source that answered with a record for a DIFFERENT coin than the id asked for: a coin id is self-certifying (`SHA256(parent ‖ puzzle_hash ‖ amount)`), so a substituted record is a failed READ -- never that coin's record, and never `coin: null`. On `.coinSpend` it likewise INCLUDES a source that answered with another coin's spend, a puzzle reveal that does not tree-hash to the spent coin's own `puzzle_hash` (or will not parse), and a spend the coin record contradicts (no record, or a record calling the coin unspent) -- each fails CLOSED rather than being served unverified. On `.coinsByParent` it INCLUDES a source that returned a child naming a different parent, which fails the WHOLE page rather than being silently filtered (a filtered page is a lineage with an invisible hole). Distinct from `WALLET_NO_CHAIN_SOURCE` and `WALLET_NOT_SYNCED`. |
| -32043 | `WALLET_RATE_LIMITED` | node | `control.wallet.balance`/`.coins`/`.coinById`/`.coinSpend`/`.coinsByParent` refused: the GLOBAL coinset-fallback rate bound is exhausted (too many arbitrary-address reads hit the expensive fallback in a short window). Defense-in-depth against an open-read amplification/oracle sweep; back off and retry. The bound charges only reads that actually REACH a chain source: the cheap local-DB fast path is never gated, and neither is an answer served from the node's own chain-read cache, which sends nothing and so amplifies nothing. Charging a cached answer bounds no egress and starves the misses the bound exists for -- a client polling one coin drains the bucket with reads that never leave the machine, and the bucket then cannot refill while that client runs. |
| -32044 | `WALLET_NODE_SPEND_DISABLED` | node | `control.wallet.broadcast` refused: the bundle requires a signature from one of the NODE's OWN custodied keys while `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off (§18.12). The node relays bundles somebody else signed on every install; sending its own money is a separate, default-OFF custody decision, and a caller could otherwise sign through the node and hand the bundle straight back. Retrying cannot help: the remedy is a bundle that does not spend the node's coins, or the flag. |
| -32060 | `PEER_PING_REFUSED` | node | `control.peers.ping` (§7.4a) refused BEFORE dialing: a ladder is already running on this node (single-flight), or the start-rate bound for the window is exhausted. Anti-amplification — the method makes this node dial a caller-supplied address. Distinct from a ladder that ran and reached nothing, which is a RESULT (`verdict: "unreachable"`), not an error. |

Read-path and upstream errors outside this table are relayed verbatim; this catalogue governs what
the **shell** mints plus the cross-boundary codes a client must be able to branch on.

### 10.4. Miss-path amplification bounds and the explicit proxy fallback (dig_ecosystem#2007)

The content miss handler (`crate::Node::miss_outcome`, feeding `content_miss_envelope` /
`range_miss_envelope` / the peer range-stream miss) runs a DHT `find_providers` lookup — and, on an
explicit `proxy`, a full multi-source fetch — on behalf of the CALLER. The `dig.getAvailability`
batch's not-held → holder-hint enrichment (`Node::availability_answer`) runs the SAME
`find_providers` lookup per not-held item. Both spend this node's network bandwidth, so a caller who
cannot name any content it actually wants could otherwise amplify this node by naming arbitrary
`(store_id, root, retrieval_key)` triples — and a `getAvailability` batch is the LARGEST such vector,
naming up to `MAX_AVAILABILITY_ITEMS` (= 512) content ids in one request. FOUR bounds govern the
path, and the first of them (10.4.0) runs in FRONT of the per-requestor budget of 10.4.1:

10.4.0. **Inbound admission on the mTLS peer surface (dig-sex SPEC 8.5, dig-node#269).** Every
inbound `dig.getAvailability` and peer JSON-RPC request MUST pass a concurrency meter BEFORE the
request is read, decoded or dispatched — ahead of the per-requestor token bucket of 10.4.1. A refused
request is answered `-32000` with `message: "request refused"` and `data.reason` naming the LIMIT that
was reached, never the standing of the peer: `unauthenticated`, `request too large`,
`node at capacity`, `peer at capacity`, `relay budget exhausted`, `meter full`. A second
implementation MUST produce these answers and MUST be able to interpret them; they say "retry later"
(or, for the first two, "this request is not admissible as framed"), never "you are banned".

- **Metered by the authenticated identity.** The meter key MUST be the mTLS-verified `peer_id` of the
  session, as lowercase 64-hex. A session carrying no such identity is REFUSED (`unauthenticated`) —
  never admitted unmetered, and never coerced into a placeholder key. Admitting an identity-less
  request unmetered would make presenting no identity the cheapest way out of the meter, and metering
  every such request under one shared key would let a single caller exhaust the allowance of everyone.
  A caller-less session therefore serves only the range and module-range paths.
- **A batch past `MAX_AVAILABILITY_ITEMS` (= 512) is refused WHOLE**, with reason `request too large`,
  rather than answered as a truncated 512-item prefix. The clamp is on the quantity the caller chose,
  applied at the boundary, and it MUST equal the batch size the node advertises it answers: a clamp set
  below the advertised limit would refuse work this contract says is served. A batch AT 512 MUST be
  answered in full.
- **Two pools, and the property they buy.** The FIRST concurrent unit of work of a peer is charged to a
  reserve whose per-peer share is exactly 1, sized `RESERVED_FIRST_SLOTS` = `MAX_INFLIGHT_PEER_CONNECTIONS`
  (= 512); every further concurrent unit of that peer, and all relayed work, draws on the shared
  node-wide pool. The reserve grants no peer any extra concurrency — the total concurrent share of a
  peer is unchanged, and only the pool its first unit is charged to differs.

  The normative property is this: **a bounded number of free identities MUST NOT be able to deny the
  peer surface to everyone else.** With a single shared pool, the identities needed to hold the
  node-wide ceiling is `global_ceiling / per_peer_share` — a small constant, each identity costing one
  self-signed keypair and each staying inside its own share so the per-peer limiter never fires.
  Reserving the first unit makes the cost of denying an honest peer **one identity AND one held
  connection per slot** — linear, and bounded by the connection cap the node already enforces. An
  implementation MAY choose different numbers; it MUST NOT make denial cheaper than one held connection
  per denied slot.
- **A peer holding no work in flight is admitted while a busy node sheds**, for up to
  `RESERVED_FIRST_SLOTS` such peers concurrently. Shedding under load MUST
  come out of the shared pool, so load-shedding degrades the peers that are already consuming
  concurrency rather than locking out peers that are asking for the first time.
- **The relay budget is configured and VACUOUS on this node.** Nothing here constructs relayed work, so
  the separate relay ceiling is satisfied because the case it governs never occurs — not because it is
  enforced. It is retained so that the first producer of relayed work inherits a budget rather than an
  omission. It is recorded as vacuous rather than listed as an active rule, because a limit nobody
  reaches and a limit nobody applies are indistinguishable from the number alone.

10.4.1. **Per-requestor rate limit.** A token-bucket limiter (default burst
`DEFAULT_MISS_LOOKUP_BURST` = 16, refill `DEFAULT_MISS_LOOKUP_REFILL_PER_SEC` = 4/s) sits in FRONT of
both the DHT lookup and the proxy fetch, keyed by REQUESTOR identity — the mTLS-verified `peer_id`
for a peer-origin request, the connection IP for an anonymous/gateway HTTP request, one shared bucket
for the trusted operator loopback. An over-budget requestor's miss is refused with `-32003`
`CONTENT_MISS_RATE_LIMITED`; a DIFFERENT requestor draws from its own bucket and is unaffected. The
tracked-requestor table is bounded (`MAX_TRACKED_REQUESTORS`), evicting only idle (full) buckets so
eviction can never weaken a live bound. The oracle bound is enforced upstream: a caller that cannot
name a concrete 64-hex `ContentId` (`miss_content_for` returns `None`) triggers no lookup at all.

The SAME budget bounds the `dig.getAvailability` enrichment, spent **one token per not-held item**
that would trigger a lookup (NOT one token per batch — a single per-batch check would still admit 512
lookups for one token and re-open the hole). When the requestor's bucket is exhausted, the remaining
items answer not-available WITHOUT a lookup — the redirect/`providers` hint is best-effort enrichment,
so dropping it leaves the availability answer itself (held vs not-held from local inventory)
unchanged. So the number of `find_providers` lookups a single requestor can cause via
`getAvailability` — across ANY batch size and ANY call rate — is bounded by its per-requestor token
budget, identical to the single-item legs.

10.4.2. **Candidate cap.** A redirect names at most `MAX_REDIRECT_PROVIDERS` (= dig-dht's
`MAX_ADDRESSES_PER_RECORD`) holders (§10 `-32008`); `find_providers` already caps the addresses per
record. This node NAMES holders but never dials/probes them — reachability is the requestor's job via
its own §5.2 ladder (NAT asymmetry: "peers I can reach" ≠ "peers the requestor can reach", and
probing-on-miss would itself be the amplification vector).

10.4.3. **Explicit proxy fallback (`params.proxy`, default OFF).** A requestor that cannot itself
reach any named holder (NAT asymmetry) MAY set `proxy: true` on `dig.getContent`/`dig.fetchRange`.
Under the §10.4.1 budget, the node then fetches the resource over the identical chain-anchored,
merkle-verified fetch path and serves the bytes back, instead of redirecting. Automatic
fetch-on-miss stays OFF — the caller must ask. The proxy serves bytes but the middle node does NOT
become a holder (a remote/`Peer`-origin read never triggers reshare/backfill — the reshare
amplification boundary, §14.3/§19), so proxying cannot be used to plant attacker-chosen inventory.

10.4.4. **The forwarded ask (dig_ecosystem#3128).** WHEN ENABLED (§10.4.6 — it is opt-in and defaults
OFF), a miss MUST also ask this node's CONNECTED POOL peers the same question over the existing
`dig.getAvailability` verb, and MUST merge the `providers` they name into the answer it was already
building. Every requirement in this clause is conditional on that gate; a node with the feature
disabled MUST forward nothing, and its miss answer is the DHT-only one §10.4.1-10.4.3 describe. This
is what makes discovery recursive:
a holder reachable through connections this node already holds is named even when no DHT record here
can point at it. No new verb, address struct or result type is introduced — the hop budget rides
`params.redirect_depth` and the answer rides the existing `providers` array.

- **A peer that does not answer MUST NOT be read as "found nobody" (dig-node#273).** A `result` frame
  is an ANSWER even when its `providers` array is empty or absent — that peer looked. A JSON-RPC
  **error** frame is a REFUSAL, a frame that is neither is UNREACHABLE, and a budget that expires is a
  TIMEOUT. Those three establish NOTHING about whether the content exists and MUST be distinguishable
  from the one that does.

  This REPEALS the earlier reading, which collapsed all four into an empty `providers` list. The
  collapse let one slow or hostile peer manufacture an authoritative absence: a hop that simply refuses
  every ask suppressed every holder downstream of it AND left the requestor confident about it, which
  is a censorship primitive costing one field.

- **Ordering is normative.** This node's own DHT findings MUST lead the merged list and forwarded
  records MUST follow, deduplicated by `peer_id` keeping the FIRST occurrence. The requestor dials in
  list order and the list is truncated at `MAX_REDIRECT_PROVIDERS` (§10.4.2), so appending is what
  makes that cap non-displacing: a peer answering with a full slate of fabricated holders spends only
  the tail and can never evict a holder this node found itself.
- **The DECISION is `dig_sex::discovery`, not this node.** Whether to forward, to whom, and with what
  budget remaining MUST be decided by `dig_sex::discovery::decide_forward` against
  `RecursionConfig`, and the switch MUST be parsed by `dig_sex::discovery::parse_enabled`. This node
  owns only the WIRE — the verb, the framing and the dial. A second implementation of this decision is
  forbidden: dig-node carried one, and it disagreed with the canonical crate on both bounds below.
- **Depth.** The ask carries `redirect_depth + 1` on the wire, and a request whose remaining budget is
  zero MUST forward nothing (it still answers from the DHT). The budget is `RecursionConfig::hop_cap`
  (= 2), which is distinct from `REDIRECT_HOP_CAP` (= 4): the redirect bounds how far a CALLER is
  bounced, the hop cap bounds how far a QUESTION travels at other nodes' expense.
- **A request shape that CANNOT CARRY a hop counter MUST be treated as fully spent.** Stated over the
  CLASS, not over one message type: any inbound shape with no field able to hold a hop count MUST
  declare its budget already spent and MUST forward nothing. A recursion started from such a shape
  could not be bounded by anything, so the only safe reading is zero. The dig-nat mux
  `AvailabilityRequest` is today's instance — it has no such field — but a second hop-counter-less
  shape MUST inherit this without the clause being rewritten.
- **An UNREADABLE hop budget MUST be refused, never read as a full one.** A `redirect_depth` that is
  present and cannot be parsed as a hop count MUST yield
  `ForwardRefusal::UnreadableHopBudget` and forward nothing. A request whose hop budget cannot be read
  is a request whose reach is unbounded, and the field is attacker-supplied. An ABSENT `redirect_depth`
  is NOT unreadable — it denotes an originating request and carries the whole budget.

  The REDIRECT leg keeps its tolerant reading of the same field (unreadable counts as depth 0),
  because it spends only this node's own lookup. The two readings are deliberate and MUST NOT be
  reconciled: forwarding spends OTHER nodes' bandwidth and is therefore gated more tightly.
- **Breadth.** At most `RecursionConfig::fan_out` (= 3) peers per admitted miss, and at most
  `MAX_CONCURRENT_FORWARDED_ASKS` (= 32) forwarded asks in flight node-wide. The requestor itself and
  this node's own `peer_id` MUST be excluded from the fan-out.

  **One admitted frame recruits 12 nodes: `3 + 3^2`, the SUM over hops.**
  `RecursionConfig::worst_case_nodes_recruited()` returns `fan_out ^ hop_cap` = 9, which is the
  **LEAF COUNT of the last hop only** and MUST NOT be quoted as the recruitment or the disclosure
  radius — it understates both by the intermediate hops. Against a full relay burst
  (`DEFAULT_RELAY_ASK_BURST` = 4) the figure for one requestor is `4 x 12` = **48**.
- **WHICH peers are asked MUST be RANKED, never a prefix of the pool (dig_ecosystem#3129).** The
  fan-out is selected by `dig_sex::routing::select_fan_out` from this node's own observations of how
  each pool peer has answered previous forwarded asks. Taking a prefix of the connected-pool map is
  forbidden: the map's iteration order is arbitrary but STABLE, so a prefix is a fixed arbitrary
  sample and the same handful of peers would absorb every forwarded ask for the life of the process.
  A slot in each fan-out of two or more is reserved for a peer this node has never observed, so every
  pool member can earn a score.

  **The routing identity MUST be the VERIFIED mTLS session identity** — `SHA-256(peer-cert SPKI DER)`,
  the `peer_id` this node's own handshake produced — and MUST NOT be derived from any value a peer
  supplied: not an address, not a provider record, not a dig-dht `Contact`, not any field of any
  frame. **The observations MUST be caller-observed**: the outcome and the latency of an exchange THIS
  node issued and saw complete, never a quality a peer asserted about itself. A router that rewards
  novelty while letting a peer choose its own identity or its own score is an eclipse attack — a
  hostile peer claims a neighbourhood engineered to look maximally novel and attracts every query
  (NC-12).

  Observations are node-local: never gossiped, never persisted across a restart, and keyed ONLY by
  peers presently in the connected pool. Pool membership is the liveness gate, so they carry no TTL
  and are dropped the moment the pool drops the peer — which is also what keeps the store from being
  keyed by untrusted input.
- **Self MUST be excluded from the ANSWER as well as from the fan-out.** These are two rules, and the
  fan-out exclusion does not imply the other: a peer is free to ANSWER with a record naming this node.
  Every source feeding the merged answer — DHT and forwarded alike — MUST be filtered against this
  node's own `peer_id`, satisfying §19.3 on the redirect answer and not only on the fetch/dial path.
- **A SEPARATE relay budget.** The outbound fan-out MUST be charged to its own per-requestor bucket
  (`DEFAULT_RELAY_ASK_BURST` = 4, `DEFAULT_RELAY_ASK_REFILL_PER_SEC` = 1/s), never the §10.4.1 lookup
  budget. Requestor identity keys the IMMEDIATE caller, so a relaying hop's fan-out is billed to that
  hop's allowance at its own peers; a shared bucket would let one admitted inbound frame spend a
  victim's budget across every peer it holds, and would let a caller convert cheap-lookup tokens into
  fan-out at third parties. Every refusal degrades the answer (fewer named holders) and MUST NOT fail
  the request.
- **Forwarded records are HEARSAY.** They are offered as candidates to DIAL, where the whole-resource
  merkle bind against the chain-anchored root is what admits bytes, so a fabricated holder costs one
  wasted dial. They MUST NOT be stored, re-served as this node's own authoritative claim, or published.
- **A NOT-FOUND MUST cascade; an UNPROVEN absence MUST NOT (dig-node#273).** A node whose search named
  no holder MUST answer:
  - the plain not-found, when every leg it consulted answered — the absence is established; or
  - `-32017` `CONTENT_MISS_INCONCLUSIVE`, when any consulted leg timed out, refused, or was
    unreachable — the absence is unproven and the request MAY be retried.

  **The condition, its number and its semantics are DEFINED BY `dig-rpc-protocol`**
  (`ErrorCode::ContentMissInconclusive`, origin `Peer`), not by this document. dig-node ADOPTS it and
  names the variant rather than the integer; the number above is reproduced for readability only and
  the crate is authoritative if the two ever differ. A repo SPEC that re-declares a contract it does
  not own is how the two silently drift apart.

  **WHICH unasked path it was decides whether the absence may still be claimed.** A node that
  consulted no peer is not one case but two, and they carry opposite answers:

  - **Recursion is DISABLED on this node** (including: no forwarded leg installed at all) — the plain
    not-found. Asking was never part of this node's answer, so nothing was withheld and the answer
    stands on the DHT leg exactly as it did before the recursion existed. This is the stock posture,
    and reporting it as inconclusive would make every miss on every default build unprovable — a
    different lie, in the opposite direction, arriving by default rather than by attack.
  - **Every other reason** — a spent hop budget, a spent or unreadable time budget, a spent relay
    allowance, no eligible peer, no free concurrency slot, a walk already claimed by another path —
    `CONTENT_MISS_INCONCLUSIVE`. On a node where the recursive ask IS part of the answer, a leg that
    was supposed to run and did not leaves the search cut short. Calling that a proven absence tells
    the reader to stop looking because this node ran out of budget, which is a fact about this node
    and not about the content. Under a burst the saturation cases are the COMMON path, so collapsing
    them would turn load into manufactured not-founds exactly when the network is busiest.

  The DHT leg is subject to the same rule: a provider walk that FAILED (no reachable DHT peer, a
  transport error) is not a walk that found nobody, and the absence is unproven. `absence_established`
  is the CONJUNCTION of both legs having finished — deriving it from the forwarded leg alone left the
  DHT leg with no way to clear it, which on a stock node made the field a constant `true`.

  **EVERY layer of the provider-locator chain MUST preserve that distinction.** The chain a node
  installs (a union over its discovery sources; a self-exclusion filter; a resource→capsule fallback)
  is *best-effort for FINDING* — one source erroring MUST NOT remove what another source found — but
  it is **strict for ABSENCE**: a layer whose result is EMPTY and which had a source FAIL MUST report
  that failure rather than an empty set. A layer that returns `Ok([])` for a failed sub-query makes the
  conjunction above unreachable, because the failure never reaches the leg that computes it; that is a
  false `absence_established: true` for content that exists, and it needs no forged message to occur —
  a start-up before any DHT peer answers, a partition, or an eclipsed routing table produce it. It is
  worse on a stock node, where the recursive ask ships disabled and this conjunct is the whole search.
  A NON-empty result is not an absence claim, so a failure beside it is immaterial and MUST NOT cost
  the caller a holder.

  **A located holder and an established absence are MUTUALLY EXCLUSIVE.** `absence_established` MUST be
  `false` whenever the answer names ANY provider, on every surface that carries it — the emptiness is
  part of the claim itself and MUST NOT be left to a caller's control flow. dig-node enforces this in
  `LocatedHolders::establishes_absence()`, which requires an empty record set AND both legs finished.
  Deriving it from conclusiveness alone was correct only at the one call site that happened to ask
  inside an emptiness guard; `dig.getAvailability` asks unconditionally and so returned
  `absence_established: true` in the same object that named a holder (dig_ecosystem#3159). A surface
  that names who holds the content while asserting it established the content's absence is lying about
  where content is, which is the manufactured not-found this clause exists to prevent.

  `dig.getAvailability` additionally carries `absence_established` on its miss answer, defined by
  `dig-rpc-protocol` (`AvailabilityAnswer::absence_established`). It has **THREE** states and dig-node
  MUST NOT collapse them:

  | state | meaning | dig-node's reading |
  |---|---|---|
  | `true` | the responder reached everything it meant to reach | the absence is established |
  | `false` | the responder looked and its own search was incomplete | unproven; keep looking |
  | ABSENT | the responder makes NO claim — it cannot describe its search at all | unproven; keep looking |

  ABSENT is **not** `false` and MUST NOT be defaulted. Reading it as `true` turns an unknown into an
  assertion of absence, which is the manufactured not-found this clause exists to prevent, arriving
  through the compatibility door rather than through an attack. The cost — a mixed network reporting
  more retries — is the right one, because an over-reported inconclusive costs a retry while an
  over-reported absence costs content that exists and cannot be found. It does not arrive by default
  either: the forwarded leg ships DISABLED, so a node that asks no peer never reads the field.

  A node emits the field only when a search actually ran; a node that consulted nothing OMITS it,
  because inserting `false` would report an incomplete search that never happened.

  An establishment MUST come from an item that CARRIES it. A responder's `items` array that is EMPTY
  claims nothing and MUST be read as ABSENT — folding it to the identity would let a responder assert
  a proven absence with the cheapest possible message on the wire.
- **The TIME budget MUST be carried DOWN and DECREMENTED, never restated (dig-node#273).** A hop asks
  its peers SEQUENTIALLY, so a hop with `h` hops remaining needs `leaf + fan_out x work(h - 1)`. A
  parent that grants each child a fixed per-ask timeout grants it LESS TIME THAN THE WORK IT IS ASKING
  THAT CHILD TO DO — at the default `fan_out = 3` a child needs 15s and was given 5s — so the second
  hop times out under any load and, before this clause, that timeout was indistinguishable from a miss.
  The recursion was arithmetically depth-1 while appearing to work.

  - The budget rides its OWN field, `params.budget_ms`, and MUST NOT be folded into
    `redirect_depth`: the time budget is monotone DECREASING and the depth monotone INCREASING, so one
    integer cannot carry both, and overloading it would let a hop buy itself hops by claiming time.
  - `budget_ms` likewise has THREE states, defined by `dig-rpc-protocol`
    (`GetAvailabilityParams::budget_ms`), and dig-node MUST NOT collapse them:
    - **ABSENT** — unbudgeted. The responder applies its own policy; an originator derives its budget
      from the work it is about to authorise.
    - **`0`** — EXHAUSTED. The hop MUST NOT ask onward at all, and MUST NOT claim the absence, having
      established nothing. Reading a zero as absent would let a spent budget silently buy a fresh one
      at every hop, which is the unbounded reach the field exists to bound.
    - **any other value** — the granted allowance, honoured exactly up to the ceiling below.
  - It MUST be CLAMPED at ingress to `MAX_FORWARDED_ASK_BUDGET` (= 65s, the derived worst case at the
    default bounds). The field is attacker-supplied, and without a ceiling one hop naming a ten-minute
    budget holds an inbound request — and one of the 32 concurrency slots — open for ten minutes.
  - A hop MUST NOT hand a peer more time than it was itself granted, and MUST stop asking when the
    budget is spent. Peers left unasked make the absence UNPROVEN.
- **The same ask MUST be walked at most once per node (dig-node#273).** A request carries an opaque
  16-byte `params.ask_id`, minted by the originator and echoed unchanged by every hop; a node that has
  already forwarded that id MUST NOT forward it again. Excluding the requestor stops an immediate echo
  but NOT a diamond: in any graph that is not a tree the same ask reaches one node by two paths, and
  without an identity neither arrival recognises the other, so the graph re-walks itself and the real
  cost far exceeds `fan_out ^ hop_cap`.

  The id MUST NOT be derived from the content (two independent readers asking about the same capsule
  would collide, silently refusing the second) nor from the requestor (that would publish who is asking
  to every hop, widening the §10.4.5 disclosure). A request carrying no readable id MUST be treated as
  a NEW question, never as a duplicate — that is the honest degradation for an older peer, and the
  alternative hands anyone a way to suppress the whole forwarded leg by omitting a field.
- **The MERGE is `dig_sex::discovery::merge_answers`, not a local copy.** It caps the HEARSAY portion
  only and tags every record `FirstHand` or `Hearsay`. Capping the merged set instead would let one
  peer returning a full slate of fabricated holders evict every genuine holder for free — a denial of
  the answer achieved without holding anything.

10.4.5. **Privacy.** A miss discloses the requested `(store_id, root, retrieval_key)` to the middle
node (it must, to locate holders). The `proxy` path additionally discloses to the serving holder that
someone wanted that resource — the SAME disclosure a direct read from that holder would make. For the
redirect and proxy paths alone, no NEW party learns the request beyond those a direct read would
already involve (cross-ref dig_ecosystem#2006/#1934 on read-path metadata exposure).

**The forwarded ask (§10.4.4) breaks that property deliberately, and it MUST be stated rather than
inherited.** Enabling it means a miss discloses the requested triple to parties a direct read would
never have involved:

- Up to `RecursionConfig::fan_out` (= 3) of this node's connected pool peers learn the triple per
  admitted miss, and each of them may disclose it to 3 of ITS peers, recursively to `hop_cap` (= 2).
  The disclosure radius of one admitted frame is therefore `3 + 3^2` = **12 nodes** — the SUM over
  hops, since an intermediate node learns the triple exactly as a leaf does — none of which the
  requestor chose, contacted, or can enumerate. Against a full relay burst that is **48**.
- Those peers are selected by THIS node's pool membership, not by the requestor. A requestor cannot
  predict, restrict, or audit who ends up learning what it asked for.
- The disclosure happens on a MISS, which is precisely the case where the requestor has not yet
  decided to contact any holder — so it is not a disclosure a completed direct read would have made
  anyway.

Two limits are real and MUST NOT be overstated into an anonymity claim:

- **The requestor's identity is not carried past the first hop.** A forwarded ask contains only the
  content item and `redirect_depth`; each receiver authenticates the FORWARDING node's `peer_id` over
  mTLS and learns nothing about who originally asked. So downstream nodes learn WHAT was asked, not BY
  WHOM. This is a property of the message, not a defence against timing or traffic correlation, and it
  MUST NOT be described as anonymity.
- **No HEARSAY is retained.** Forwarded records are merged into one answer and never stored,
  re-served or published (§10.4.4), so a hop's claim lives in a node's memory for the life of one
  request — but a peer is free to log what it was asked, and nothing here prevents that.

  This is narrower than the absolute "nothing is retained" that stood here previously, and the
  disclosure claim above is unaffected. What a node MAY retain is its OWN FIRST-HAND knowledge
  (§10.4.7), which it necessarily already had; what it MUST NOT retain is anything a hop told it. The
  widened radius this clause bounds is about what a hop LEARNS from being asked, and caching a record
  this node established itself does not widen it.

This is why the forwarded ask is **opt-in** (`DIG_NODE_FORWARD_ON_MISS`, default OFF, §10.4.6):
widening the disclosure radius of every miss on a node is an operator's decision. A node with the
feature disabled retains the narrower property stated in the first paragraph.

10.4.6. **The forwarded ask is OPT-IN.** `DIG_NODE_FORWARD_ON_MISS` (default **OFF**; only an explicit
`on`/`1`/`true`/`yes`, case-insensitive, enables it) governs §10.4.4. It is resolved ONCE at engine
construction, so a node's amplification posture is fixed for its lifetime. Disabled, a miss answers
from this node's own DHT lookup and the answer is byte-identical to one produced before the forwarded
ask existed. The switch MUST be parsed by `dig_sex::discovery::parse_enabled`, which FAILS CLOSED:
any value it does not recognise — a typo, an empty string, a value from a newer config format —
disables recursion, because a mistake MUST NOT be able to enable a network-wide amplifier.

The default is OFF because the leg spends OTHER nodes' bandwidth: one admitted frame recruits
**12 nodes** (`3 + 3^2`, the sum over hops — 48 against a full relay burst), each of which also runs a
DHT walk, while the strictly cheaper, node-local `proxy` leg (§10.4.3) is already opt-in. A path that
amplifies more than an opt-in path MUST NOT be gated less than it.

10.4.7. **The first-hand holder cache (dig-node#275).** A node MAY remember which peers it
established FIRST-HAND are holding which content, so a later request dials a known holder without
repeating discovery.

- **FIRST-HAND ONLY. Hearsay MUST NOT be cached.** A first-hand record is one this node obtained
  itself; a hearsay record is one a hop relayed. This keeps §10.4.4's *"forwarded records MUST NOT be
  stored"* intact, and it is a security property rather than a tidiness one: a cache admitting hearsay
  would let one lying hop plant a fabricated holder that this node then re-serves as its own knowledge
  for the whole TTL, which is a far better attack than lying once.
- **It bounds and expires.** Keyed by `ContentId`; TTL **300s**; at most 4096 keys, evicting expired
  entries first and then the oldest by insertion. Misses are stranger-driven — anyone may ask about
  content this node does not have — so an unbounded cache of peer claims is a memory target a stranger
  fills for free.
  - The TTL MUST NOT be `ADVERTISED_TTL_SECS` (3600s). That constant is how long a holder's OWN SIGNED
    announce is treated as live; what this cache holds is an unsigned DHT lookup ANSWER, relayed by
    whichever node the walk reached first, and pricing the second at the lifetime of the first lends it
    a warrant it does not carry.
  - What the TTL bounds is a DISPLACEMENT window: first-hand records are prepended at the merge and the
    hearsay tail is cut at `MAX_REDIRECT_PROVIDERS`, so a fabricated first-hand slate EVICTS genuine,
    recursively-discovered holders for as long as it is remembered, and every read inside the window
    renews it. 300s still spares rediscovery across the repeated lookups one download session makes.
  - The TTL is a CEILING, not the whole rule: each record's own `expires_at` is honoured too, so a
    cached entry can never outlive the claim behind it.
- **An EMPTY slate MUST NOT be cached.** "I found nobody" is a fact about one moment; retaining it
  would suppress rediscovery for the whole TTL, turning one unlucky lookup into an hour of manufactured
  absence — the same failure §10.4.4 repeals on the wire.
- **It is a discovery shortcut, never an answer.** A cache hit replaces the DHT walk ONLY; the
  forwarded ask still runs. Short-circuiting the whole search would mean a node holding any first-hand
  record stops asking its peers for the rest of the TTL, silently disabling the recursive enrichment.
- **It MUST be invalidated when its slate reaches nobody**, at the same point dig-dht SPEC §6.8's
  cached answer is forgotten. Otherwise it replays the exact candidates just proven unreachable.
- **In memory only; never persisted.** A record of who holds what is also a record of what this node
  looked for, so it is not written to disk and does not come under NC-2 at-rest sealing. The process
  ending forgets it.
- Every cached entry remains a candidate to DIAL and never a fact (NC-12): the whole-resource merkle
  bind against the chain-anchored root is what admits bytes, so a stale entry costs one wasted dial.


---

## 11. Release and CI contract

11.1. **Nightly cron + manual dispatch (NOT per-merge).** Releases are batched to a nightly cron
plus manual dispatch — NOT cut on every merge to `main` (dig_ecosystem #590/#592; the shape is
copied from the reference `dig-updater`). One orchestrator, `.github/workflows/nightly-release.yml`,
triggers ONLY on `schedule: cron '0 0 * * *'` (midnight UTC — GitHub cron is always UTC, and a
top-of-hour cron MAY be delayed under load, which is acceptable since both channels are idempotent)
and `workflow_dispatch` (inputs `channel` = `both`|`stable`|`nightly`, default `both`; `force`
boolean, default `false`). It MUST NOT trigger on `push` to `main`.

- **Stable channel:** cuts a `vX.Y.Z` release when — and only when — the `[workspace.package].version`
  in the root `Cargo.toml` has advanced beyond the newest `vX.Y.Z` tag (the skip-if-already-tagged
  check IS the version-changed check). Cutting = `git-cliff` regenerates `CHANGELOG.md`, commits it
  to `main` as `chore(release): vX.Y.Z`, tags THAT commit, and pushes commit + tag with
  `RELEASE_TOKEN`. The pushed `v*` tag fires `release.yml` (§11.2/§11.3), which publishes a GitHub
  Release with `prerelease: false`. A stable release is the ONLY release that may move `latest`, and
  it moves it in a separate PROMOTION step gated on the asset verification below — never as a side
  effect of attaching assets (§11.1b).
- **Force re-cut (guarded).** `force: true` bypasses skip-if-tagged and re-cuts the current version
  (moving the tag onto a fresh changelog commit; `main` is never force-pushed). It MUST be refused
  — non-zero exit, clear error — when BOTH: (a) a PUBLISHED (non-draft) Release exists at the tag,
  AND (b) the tag points at a commit DIFFERENT from the one this run would build (that would
  overwrite shipped binaries with unreviewed code under the same version). Force MAY proceed for a
  same-commit re-cut (failed-build retry) or a tag with no published release (a tag repair). A
  force-moved tag breaks git tag-immutability; because dig-node updates are gated by the dig-updater
  signed feed (an Ed25519 signature over the update descriptor, verified before apply), that
  signature — not the mutable tag — is the integrity anchor. Ship new code by bumping the version.
- **The tag push is a request, not a guarantee.** Creating a workflow run from a pushed tag is an
  event delivery this repo does not control, and it has been observed to not occur even though the
  push succeeded. After pushing the tag the stable job MUST confirm that both `release.yml` and
  `package.yml` have a run for that tag, and MUST dispatch — against the tag ref — whichever is
  absent. Both workflows gate publication on `github.ref_type == 'tag'`, which a dispatch against a
  tag satisfies, so the dispatched run is equivalent to the event-triggered one. The confirmation
  MUST be idempotent: where the event was delivered normally, it dispatches nothing.
- **A stable release MUST carry every asset its consumers resolve — packages AND binaries.** Two
  consumers read assets out of a stable release, and satisfying one is not satisfying the release:
  dig-updater's feedsign resolves dig-node by the `.deb`/`.pkg`/`.msi` file names and fails closed on
  the ENTIRE signed manifest when they are absent (freezing auto-update for every component on the
  channel), while dig-installer resolves the raw `dig-node` and `dign` binaries through
  `releases/latest` and 404s a fresh install when either is absent. The stable path MUST verify the
  published release's asset list (`verify-release-assets.yml`) and MUST fail the release run when any
  of the fourteen names is missing:
  `dig-node_<version>_amd64.deb`, `dig-node_<version>_arm64.deb`, `dig-node-<version>-macos.pkg`,
  `dig-node-<version>-windows-x64.msi`, and — for each of `linux-arm64`, `linux-x64`, `macos-arm64`,
  `macos-x64`, `windows-x64.exe` — both `dig-node-<version>-<platform>` and `dign-<version>-<platform>`.
  Repairing a failed release by publishing only one of the two sets is NOT a repair.
- **§11.1b. `latest` MUST NOT move until the release is verified complete.** A stable release is
  assembled by two workflows that finish at different times (`release.yml` attaches the binaries,
  `package.yml` the native packages), so neither may promote it. Both MUST publish with
  `make_latest: false`, and `releases/latest` MUST be moved by a single promotion step that runs only
  after the asset verification above has passed. An incomplete release therefore never becomes
  `latest`: the previous complete release keeps serving installs, which is the required failure mode.
  The guard MUST be falsifiable — a self-test MUST assert that it FAILS an asset list carrying only
  the native packages.

  **"Verified complete" is a statement about BYTES, not about names.** An asset is complete only when
  it is present AND its upload state reports it as fully uploaded (GitHub: `state == "uploaded"`); an
  asset still being written reports `state == "starting"`. The row is created when the upload BEGINS,
  so every expected asset name can be present while bytes are still in flight, and a verification that
  counts names alone promotes a release whose binaries are truncated or absent. A reimplementation that
  reads only the name list satisfies the letter of the clause above and reintroduces exactly the race
  it exists to prevent, which is why the state is stated here rather than left to the implementation.

11.1a. **Doc-only commits never release** (the version is unchanged → the tag exists → the stable
job is a no-op). The manual-dispatch `workflow_dispatch` on `release.yml` is a build-only "does main
still build?" canary — it never publishes (publish is gated on a tag ref).

11.2. **Asset naming (HARD RULE).** Every per-OS/arch binary MUST be published under the canonical
name:

- **`dig-node-<ver>-<os>-<arch>[.exe]`** — the canonical name every downstream consumer resolves:
  the dig-installer thin-shim's preferred stem AND apt.dig.net's Linux packaging template
  (`dig-node-{ver}-linux-{arch}`, bare binary).

`<ver>` is the tag without the leading `v`. The duplicate legacy `dig-companion-*` copy (dig-node
was formerly dig-companion, #209) is NO LONGER published (#585): no consumer resolves that name from
a dig-node release — the installer's pre-rename fallback targets the SEPARATE
`DIG-Network/dig-companion` repo's own frozen historical releases, not this asset name — so it was
pure release-noise.

11.3. **Matrix + the Linux platform floor (HARD RULE).** Five assets are published:
`windows-x64` (x86_64-pc-windows-msvc), `linux-x64` (x86_64-unknown-linux-gnu), `linux-arm64`
(aarch64-unknown-linux-gnu), `macos-arm64` (aarch64-apple-darwin), and `macos-x64`
(x86_64-apple-darwin, cross-compiled on macos-14). The apt `.deb` is published for both `amd64` and
`arm64`.

**Every published Linux artifact — the raw binaries AND the `.deb` — MUST run on glibc 2.31 or
newer.** 2.31 is the supported floor, and it is a floor on the whole Linux delivery surface, not a
per-workflow choice. It clears Ubuntu 20.04+, Debian 11+, Amazon Linux 2023 and RHEL 9.

A glibc-linked binary runs on its BUILD glibc and anything newer, never anything older, so the
BUILDER IMAGE alone determines this floor. Every job producing a Linux artifact therefore builds
inside a pinned old-glibc container (`debian:11`) via `.github/actions/setup-linux-build`, which is
the single place the floor is declared. It is enforced in three ways, all of which MUST hold:

- the action asserts the container's own glibc equals the declared floor, so the image and the
  number cannot drift apart;
- `scripts/check-glibc-floor.sh` asserts every produced binary's highest glibc requirement is at or
  below the floor, and additionally FAILS a binary that carries no versioned glibc symbols at all
  (the musl substitution below); the release job re-runs it against an impossible floor to prove the
  gate can still fail;
- `verify-linux-floor` EXECUTES each published binary in `ubuntu:22.04`, `debian:12` and
  `amazonlinux:2023` containers on both architectures — a link-time claim is not proof that a binary
  starts.

**Every Linux artifact MUST be built for a `*-unknown-linux-gnu` target. A `*-unknown-linux-musl`
target is REJECTED**, and is not an acceptable substitute for the old-glibc container even though it
would satisfy the floor trivially. musl's built-in resolver is not a drop-in for glibc's: it supports
no NSS modules, handles a much narrower subset of `resolv.conf`, and historically does not fall back
to TCP when a UDP answer exceeds 512 bytes — precisely the shape of a DNS-seed record set carrying
many A/AAAA entries, which the node depends on to find its first peers. Meeting the glibc floor by
changing the C library therefore changes node behaviour and is a breaking change, not a build detail.

Raising the floor is a DELIBERATE, coordinated act: the declared value, every calling job's
`container:` image, this section, and the published docs move together. Both Linux architectures
build NATIVELY (aarch64 on the arm64 runner), so no vendored-OpenSSL cross-compile is involved.

11.3a. **The `dig-constants` genesis floor (HARD RULE).** A stable tag MUST NOT be cut while any
`dig-constants` copy in the resolved workspace lock is below **0.4.0**.

0.4.0 is the first release carrying the real DIG L2 mainnet genesis challenge. `dig-constants` 0.1.0
shipped an all-zeros PLACEHOLDER, with all six AGG_SIG additional-data domains correctly DERIVED from
that placeholder — a self-consistent set, and therefore invisible to every test, because each runtime
check compares the constant against itself. A copy below the floor puts a different chain identity
inside the binary. The rule is stated as a FLOOR over the whole pre-0.4.0 CLASS, not as an inequality
against 0.1.0: 0.2.x and 0.3.x carry the same placeholder.

It is enforced at two levels, and both MUST hold:

- `crates/dig-node-core/tests/dependency_tree.rs` asserts it against the workspace lock on every
  build, so a dependency edit that reintroduces a pre-0.4.0 copy fails CI, not the release;
- `scripts/check-dig-constants-current.sh` re-asserts it in the stable release job, BEFORE version
  resolution, so a breach means no tag exists to deploy. It fails closed on the lock: a missing
  lockfile, or one carrying no `dig-constants` at all, is refused rather than vacuously passed.

The gate additionally REPORTS, without blocking, that several `dig-constants` versions resolve at
once, naming the package that pins each. That stays advisory because those pins live in published
metadata this repo cannot edit, and every copy at or above the floor agrees on the chain identity.
Currency against the published crates.io tip is NOT required and MUST NOT be gated on: a
`dig-constants` release that advances the `chia-protocol`/`chia-wallet-sdk` line cannot be adopted
here while `dig-gossip`'s vendored `chia-protocol` fork is patched in, so a currency gate would ban
releasing rather than protect a property.

11.4. **Release hardening.** The release profile keeps `overflow-checks = true` (the read path
does offset/length arithmetic over untrusted serialized input).

11.5. **Nightly channel.** Every night (and on demand) the orchestrator builds `main` HEAD for
every OS/arch and publishes a GitHub **pre-release** — so a fresh nightly always exists regardless
of a version bump. It synthesizes a build-time version `X.Y.Z-nightly.YYYYMMDD.<shortsha>` (nothing
is committed; as a semver prerelease it sorts BELOW the plain `X.Y.Z`), publishes under a dated tag
`nightly-YYYYMMDD` AND force-moves a rolling `nightly` tag, with `prerelease: true` and **never**
`latest`. Retention keeps the newest **14** dated nightlies plus the rolling `nightly`, pruning
older dated pre-releases AND their tags together (`gh release delete --cleanup-tag`); `v*` stable
tags/releases and the rolling `nightly` are NEVER pruned. Neither `nightly-*` nor `nightly` matches
`release.yml`'s `v*` trigger, so the nightly channel never fires the stable build.

11.5a. **Both channels publish the NATIVE INSTALL PACKAGES (HARD RULE).** A release — stable OR
nightly — MUST carry the three native packages, not raw binaries alone. The beacon installs dig-node
by handing a native package to `msiexec`/`installer`/`dpkg`, and dig-updater's feed resolves
dig-node's artifacts by their native-package file NAMES, so a package-less release is one the update
system cannot resolve at all: it fails closed and no host on that channel can install or update.
Every release MUST therefore publish, under exactly these names (`<ver>` = the release's version,
which for a nightly is the synthesized `X.Y.Z-nightly.YYYYMMDD.<shortsha>`):

- `dig-node_<ver>_amd64.deb`
- `dig-node-<ver>-macos.pkg`
- `dig-node-<ver>-windows-x64.msi`

The nightly publish step MUST verify all three are present and FAIL rather than publish an
incomplete release. The packages are built by `.github/workflows/package.yml`
(`on: workflow_call`, inputs `version`, `deb_arches`, `ref` — all optional, so its `pull_request`
and `v*` tag triggers are unaffected), which both channels call, so the definitions cannot diverge.
The nightly `.deb` is **amd64 only** — the feed resolves a single Linux platform; the stable tag path
keeps both `amd64` and `arm64` because apt.dig.net serves both (§11.3).

11.5b. **The version is validated at ONE boundary, and the MSI version is derived.** Every package
build passes its version through `scripts/package-version.sh` before it reaches a dpkg control file,
`pkgbuild --version`, or the WiX `-d Version=` argument — all of which end up inside a package that
runs with elevated privilege. The script accepts, by whitelist, ONLY `X.Y.Z` or
`X.Y.Z-nightly.YYYYMMDD.<shortsha>`, and rejects everything else with a non-zero exit; it MUST also
reject a component exceeding Windows Installer's field limits (major/minor > 255, patch > 65535).

It emits two values, which differ on purpose:

- **`file_version`** — the version VERBATIM. The package file name MUST carry it unchanged, because
  the rolling `nightly` tag names no version and the feed recovers it from the asset name alone.
- **`msi_product_version`** — a numeric `major.minor.build`, since Windows Installer accepts no
  prerelease suffix. For a nightly this is `X.Y.<days since 2020-01-01>`. The date MUST occupy the
  BUILD field rather than a fourth field: Windows Installer compares only `major.minor.build`, so a
  fourth field is parsed and then ignored — the date would stop being comparison-significant at all.

The version whitelist also means a prerelease-shaped STABLE tag (`v1.0.0-rc.1`) is REJECTED rather
than packaged. That is intended: §2.4 of the ecosystem contract admits only `X.Y.Z` stable versions,
and an `-rc` MSI would carry the same ProductVersion hazards as a nightly with none of the handling.

11.5c. **The MSI upgrade invariant (HARD RULE).** For any two distinct nightly builds, the later one
MUST NOT compare LOWER than the earlier, and any pair that compares EQUAL MUST be made safe by an
explicit same-version-upgrade policy. The beacon installs with a bare `msiexec /i <pkg> /qn
/norestart`, so a violation of either half is a broken host: a LOWER comparison aborts on
`DowngradeErrorMessage`, and an EQUAL comparison falls outside `MajorUpgrade`'s `[0.0.0,
ProductVersion)` detect range — matching neither the upgrade nor the downgrade case, so the build
installs as a SECOND product under a fresh auto `ProductCode`, leaving two entries that both own the
`net.dignetwork.dig-node` service.

The mapping alone CANNOT satisfy this. The synthesized nightly version carries a DATE and a commit
sha and nothing else, so the ProductVersion is day-granular by construction, and 16 bits of build
field cannot hold a finer monotonic counter over any useful epoch (minute resolution exhausts the
field in 45 days; a sha-derived tiebreak is not ordered, which would produce the far worse LOWER
case). Two builds on one UTC day are reachable on supported paths — the `force` re-cut, and a manual
`channel: nightly` dispatch on a day the cron already ran.

The invariant is therefore held JOINTLY, and both halves are required:

- **the mapping** never decreases across builds (the day count is monotonic, and a base-version bump
  raises `major`/`minor` first);
- **`packaging/windows/dig-node.wxs`** sets `MajorUpgrade/@AllowSameVersionUpgrades="yes"`, so an
  equal version upgrades in place. This also repairs the same hazard for a stable re-install of an
  unchanged `vX.Y.Z`. WiX raises ICE61 for this by design; the warning IS the decision.

**Known consequence — a nightly Windows host cannot install a stable release of the same
`major.minor`.** Because the nightly build field is a day count, it sits above every real patch
number, so `0.96.<days>` outranks every stable `0.96.z`: `msiexec` aborts on
`DowngradeErrorMessage`, and the beacon cannot detect this because anti-rollback state is kept per
channel. This is not a regression — no nightly `.msi` existed before — but it is newly reachable. A
host switched from `nightly` back to `stable` on Windows requires an uninstall of the nightly
package before the stable one installs, until the version scheme distinguishes channels.

11.6. **Reusable build.** The cross-OS build lives once in `.github/workflows/build-binaries.yml`
(`on: workflow_call`, inputs `version` + `ref`). Both `release.yml` (stable) and the nightly channel
call it, so the two paths can never diverge on HOW a binary is produced — including the canonical
`dig-node-*` naming (§11.2) and the `dign` alias.

11.7. **RELEASE_TOKEN posture + 60-day cron caveat.** Releasing uses the `RELEASE_TOKEN` org PAT,
not `GITHUB_TOKEN` (a tag pushed by `GITHUB_TOKEN` does not trigger downstream workflows, and it
cannot push a changelog commit past branch protection). If `RELEASE_TOKEN` is absent, EVERY channel
NO-OPS with a clear `::warning::` — never a half-release. A `concurrency: nightly-release` group
(cancel-in-progress `false`) serializes runs. GitHub auto-disables a `schedule:` trigger after 60
days with no repo activity on a public repo, with no auto-re-enable — and since this cron is now the
ONLY automatic release trigger, a quiet repo can silently stop releasing. Detect with
`gh api repos/DIG-Network/dig-node/actions/workflows/nightly-release.yml --jq .state`
(`disabled_inactivity` = auto-disabled) and recover with `gh workflow enable nightly-release.yml`
(see `runbooks/release.md`).

---

## 12. Security properties (summary)

- **Never LAN-exposed:** loopback-only binds (§4.1); no `0.0.0.0` or `[::]`.
- **Anti-DNS-rebinding:** Host allowlist with 421 rejection (§4.2); CORS reflects only local
  origins (§4.3).
- **Read/control split:** read methods open to local consumers; `control.*` requires possession of
  the same-host capability file, compared in constant time, failing closed when unpersistable
  (§7.2–7.3).
- **Machine-wide auth state, not world-readable:** the control token + paired-token store live in a
  machine-wide state dir resolved identically by the daemon and the operator CLI, restricted by ACL
  to SYSTEM + Administrators + the creating user (Unix `0700`/`0600`) — never all-users-readable, so
  it is not a local privilege-escalation vector (§7.3a). The operator CLI reads the token read-only
  and never mints a rival token.
- **Untrusted scheme-handler input:** `dig-node open` (the OS `chia://`/`urn:dig:chia:` handler,
  §8.5) strictly validates its argument and launches the resolved URL without a shell.
- **Blind serving:** content reads return ciphertext + proofs; verification/decryption is the
  client's job (§1.3). The node never returns plaintext for content reads.
- **A filesystem path is never built from unvalidated caller input:** every cache/staging path is
  constructed from a VALIDATED capsule key — two canonical 64-hex ids — and a caller-supplied
  `store_id`/`root` pair that is not canonical is REFUSED (answered not-held) without any filesystem
  access. The validation is a TYPE that only the validating constructor can produce and that the path
  builders exclusively accept, so the check cannot be omitted at a new call site rather than a predicate
  each site must remember to call. Canonical 64-hex is a whitelist over an ALPHABET containing no `/`,
  `\`, `.`, `:`, NUL or control character, so it is complete by construction — unlike a blacklist of
  `..`, absolute prefixes and UNC roots, which would have to be complete against every platform's path
  grammar. Merkle verification is NOT a substitute: it proves provenance, not that a path is safe.
- **No secrets in artifacts:** the control token is generated at runtime, ACL-restricted (§7.3a),
  and never committed or logged.

---

## 13. Conformance summary

| # | Contract | Must match | Where enforced / specified |
|---|---|---|---|
| 1 | Read-plane wire contract | `rpc.dig.net` byte-for-byte (dispatch IS `dig_node_core::handle_rpc`) | §1.3, §5; `dig-rpc-protocol` + docs.dig.net Protocol pages |
| 2 | `DIG_NODE_PORT` / `DIG_NODE_HOST` names | dig-installer + apt.dig.net expectations — never renamed | §3.1 |
| 3 | Shared cache default | Byte-identical dir to the DIG Browser's in-process node when `DIG_NODE_CACHE` unset | §3.5 |
| 4 | `dig.local` addressing | dig-installer hosts entry `127.0.0.2  dig.local`; listener `127.0.0.2:80`, best-effort | §4.1–4.2 |
| 5 | Host/CORS allowlist | `dig.local` / `localhost` / `127.0.0.1` / `127.0.0.2` / `::1` (+ `chrome-extension://` origins) | §4.2–4.3 |
| 6 | Method catalogue ↔ read path | drift guard: `local` resolves, `passthrough` returns `-32601` at the pinned rev | §5.5–5.6; `tests/openrpc_drift_guard.rs` |
| 7 | Error codes | Table §10 — stable numbers + UPPER_SNAKE names + origins | §10; `src/meta.rs` |
| 8 | CLI exit codes + `--json` envelopes | Table §8.4; one JSON object on stdout | §8; `src/cli.rs`, `tests/cli.rs` |
| 9 | Service label | `net.dignetwork.dig-node` across install/uninstall/start/stop/SCM dispatcher | §2.4, §9.4 |
| 10 | Release assets | Canonical `dig-node-*` (+ `dign-*` alias), per §11.3 matrix | §11; `.github/workflows/release.yml` |
| 11 | Control-token scheme | `<state_dir>/control-token` (machine-wide, ACL-restricted, §7.3a), 64-hex, `X-Dig-Control-Token` / `params._control_token`, constant-time | §7.2–7.3a |
| 12 | Health/version/well-known shapes | §6 fields; additions additive only | §6; `src/meta.rs`, `src/server.rs` |
| 13 | Subscription persistence | `<cache>/subscriptions.json` schema-versioned, atomic, cross-process-locked | §14.1; `subscription.rs` |
| 14 | Autonomous sync fail-closed | chain-watch + gap-fill + read-path pin never serve/pull against an unconfirmable root | §14.2–14.4; `chainwatch.rs`, `lib.rs` |
| 15 | FFI C-ABI | `dig_runtime_start`/`dig_runtime_start_wallet` (wallet-only vs full) + `dig_rpc`/`dig_wallet_rpc`/`dig_free` + read-crypto `dig_read_verify_decrypt`/`dig_bytes_free` (`DIG_READ_*` codes) signatures + ownership/threading | §15, §15.1; `dig-runtime/src/lib.rs` |
| 16 | No user key is ever held or signed with | every dapp key/sign method is forwarded to the user's Sage wallet; the node's OWN operating wallet (§16.4) signs only under the §23 audit contract (tips §18.23, mirror coins §25), through module-scoped signers no RPC surface can reach | §16.2, §18.20, §23, §25 |

---

## 14. Autonomous sync — subscriptions, chain-watch, generation gap-fill

The node engine keeps its held content current WITHOUT being asked: it watches the chain for the
stores it subscribes to, proactively pulls the generations it is missing, and pins every serve to the
chain-anchored root. All of this fails **closed** — an unconfirmable root is never served against or
pulled.

**Bring-up.** The chain-watch + gap-fill loop is started by the OS-service bring-up as part of the
peer network: `dig-node run` (and the Windows SCM entrypoint) call `peer::spawn_peer_network`, which
installs the P2P content engine + the DHT inventory refresher and spawns the chain-watch loop
(`crate::chainwatch`). It is gated by `DIG_PEER_NETWORK` — ON by default; `off`/`0`/`false` opts a
standalone read-only node out of the whole peer network (pool + DHT + watcher), leaving the HTTP read
path serving. Bring-up is best-effort and detached: a failure is recorded on `control.peerStatus` and
never blocks reads. The in-process FFI host (`dig-runtime`, §15) does NOT run this — the browser is a
consumer, so its node installs no P2P content and runs no watcher (its in-process trust boundary).

### 14.1. Subscriptions

A **subscription** is a store the node intends to actively HOLD, WATCH, SYNC, and PUBLISH. It is
DISTINCT from the durable capsule inventory (the `.dig` modules under the cache dir): the inventory
answers "what does this node currently hold?", the subscription set answers "what does this node
intend to keep current?". A store MAY be subscribed before any of its modules are held (the watcher
pulls them down), and a module MAY be held without a subscription (a one-off cached read).

- **Persistence.** The set is persisted to `<cache>/subscriptions.json` (next to `config.json`, so it
  shares the cache's writability + lock handling). The on-disk document is
  `{ "version": <u32, currently 1>, "stores": [<lower-case 64-hex store id>, …] }`. The schema is
  **additive-only** (a future per-store option is a backwards-compatible field; a bump never removes or
  repurposes a field).
- **Normalization.** Store ids are trimmed + lower-cased on insert, de-duplicated, and kept in
  insertion order. A malformed (non-64-hex) entry MUST be dropped on load, never admitted to the
  watched set.
- **Tolerant load.** A missing, empty, or unparseable file is an EMPTY set (never an error). A legacy
  bare `{ "stores": [...] }` document (no `version`) MUST still load.
- **Atomicity.** Writes MUST be atomic (temp-file + rename) and serialized by the SAME cross-process
  advisory lock the `config.json` read-modify-write uses, so two DIG processes sharing the cache (the
  browser's in-process node + the standalone node) cannot lose each other's subscription updates.
- **Management.** The set is managed by the node-owned control methods `control.subscribe`,
  `control.unsubscribe`, and `control.listSubscriptions` (delegated to the node by the shell, §5.5/§7).
  `subscribe` is idempotent (re-subscribing is a no-op); `unsubscribe` of a store that is not
  subscribed is a no-op; the RPC echoes the EXACT normalized id it persisted so the echo can never
  disagree with `listSubscriptions`.

### 14.2. Chain-watch loop

A background loop polls each SUBSCRIBED store's CHIP-0035 singleton to detect a newly-confirmed
generation.

- **Interval.** The poll interval is `DIG_NODE_WATCH_INTERVAL` seconds, defaulting to `30` and
  **floored at `1` s** (a `0`/unparsable/unset value ⇒ default; the floor prevents a mis-set value from
  flooding coinset).
- **Per-store decision (fail-closed).** After resolving the store's chain-anchored tip root — using the
  SAME anchored-root resolver the read path uses (§14.4) — the watcher decides:
  - chain read failed (`Err`) → **Skip** (never gap-fill against an unconfirmable root);
  - no confirmed generation (`Ok(None)`) → **Skip**;
  - the confirmed tip is already held locally → **Skip**;
  - the confirmed tip is NOT held → **GapFill** `(store_id, tip)` (§14.3).
- A failed pull is simply retried on the next tick.

### 14.3. Generation gap-fill

Gap-fill is the actuator that pulls a missing generation for `(store_id, root)` from another node,
VERIFIES it against the chain-anchored root, and lands it in the node's cache. A module that arrives at
a root OTHER than the confirmed root MUST be rejected (never cached or served).

- **Two triggers.** (a) **Proactive** — the chain-watch loop (§14.2) for subscribed stores, so the node
  *actively seeks other nodes to pull missing generations* rather than only reacting to reads.
  (b) **Backfill-on-miss** — when a read is satisfied from another node or the upstream rather than
  from local disk, the node background-backfills the whole capsule so the NEXT read of that resource is
  served locally (deduplicated: a backfill already in flight for `store:root` is not started twice). This
  dedup spans BOTH whole-capsule transports: the §21 backfill here and the §21.3 P2P reshare warm claim
  ONE shared single-flight gate keyed `(store, root)`, so a read starts at most one whole-capsule pull no
  matter which leg wins, and the shared cap bounds concurrent distinct-generation acquisitions across the
  two legs together. Enabled by default; toggle with the `DIG_NODE_BACKFILL_ON_MISS` environment variable.
- **Fail-closed.** Gap-fill never pulls against an unconfirmable root (the §14.2 decision gates it).
- **Verification invariant.** Every served module is verified against the chain-anchored root at SERVE,
  no matter how it arrived — a client read, a §21 whole-store sync, or a proactive/backfill gap-fill.
- **Verify-before-announce invariant.** A synced capsule MUST ALSO pass the chain-anchored verification
  BEFORE it lands in the cache, because landing a capsule makes this node a DISCOVERABLE holder of it
  (§14.1) — an announcement, not merely a local copy. The node resolves the store's chain-anchored root,
  re-hashes the downloaded module against it, and refuses anything that is not the store's confirmed
  generation, so the module never reaches disk and is never announced. The serve-time gate is not
  sufficient on its own: a node that advertises a capsule poisons holder reputation and multiplies it
  through the reshare flywheel whether or not any later read verifies it. This is the SAME chain-anchored
  check the reshare leg applies at its own seam — one verification shape at every seam that admits a capsule.

### 14.3a. Whole-capsule download — two paths, chunked first

Landing a whole `.dig` for `(store_id, root)` is the mechanism BOTH gap-fill triggers and the
control-plane sync run on. The node MUST attempt these paths in this order:

1. **The chunked `dig.getCapsule` JSON-RPC** (`POST` on the upstream base URL). The node pages the
   capsule in windows of at most **3 MiB** — the upstream's own per-response ceiling — following the
   server's `next_offset` until `complete`. This path is ANONYMOUS: it MUST work on a node holding
   no §21.9 identity.
2. **The §21.9 authenticated clone** (`GET /stores/{id}/module`), attempted only when an identity is
   loaded. Retained for §21 hosts exposing no `dig` JSON-RPC.

The chunked path MUST lead, not serve as a fallback: a single-response clone cannot carry a
production-sized capsule across an HTTPS edge that caps a response body, so for real stores it is
the only path that completes.

The node MUST send the CONCRETE root it resolved and MUST NOT send `"latest"`. A server-chosen
generation would be a server choosing which generation this node caches, reshares, and announces
itself a holder of; the chain is the only authority for a store's tip.

Every window is validated before it is trusted. The node MUST reject a download whose declared
`total_length` exceeds **4 GiB**, whose `total_length` changes between windows, whose served offset
differs from the requested one, whose `next_offset` fails to advance, or whose reassembled length
differs from the declared length. Rejection is required BEFORE the bytes are gathered where the
declaration alone is disqualifying, so a dishonest upstream cannot drive an unbounded allocation or
an endless loop.

A failed download MUST be reported with the ACTUAL failure — the upstream's HTTP status, its
JSON-RPC error code and message, or the specific validation that rejected it. A diagnostic naming
causes that were not checked is non-conformant.

### 14.4. Read-path anchored-root pin

Every `dig.getContent` serve is PINNED to the store's chain-anchored tip root (#127): the node serves
against the on-chain current root or fails closed — it NEVER trusts an upstream-/host-reported root.

- For an **explicit-root** request the requested root MUST equal the resolved anchored tip; a mismatch
  is rejected. For a **rootless** request the node resolves the tip and serves against it.
- The anchored tip is resolved by the store's singleton-lineage walk. For an **explicit-root** request,
  a walk aborted by a single unparseable intermediate generation (#747 "parse next store: missing
  child") MUST NOT block a valid pinned root: the pin falls back to a BOUNDED verify that reads only the
  CURRENT unspent generation (one launcher-hint query — `digstore_chain::verify_pinned_root`), accepting
  the pinned root only when it equals the live on-chain root. This is fail-closed and preserves #127
  anti-rollback (a stale/never-anchored root is still rejected). A rootless request has no candidate to
  bounded-verify and relies on the walk.
- The pin fails closed with `-32005 ROOT_NOT_ANCHORED` (§10) on: a root mismatch, an unreachable chain,
  a store with no confirmed generation, or a rootless request under enforcement.
- The pin is ENFORCED by default. The ONLY opt-out is the explicit `DIG_NODE_PIN=off` (also `0`/`false`)
  environment variable, a named offline/local-development escape hatch — never the default. The pin is
  a NODE-side gate; clients still verify the returned proof against their own trust root regardless, so
  the opt-out only relaxes the node's serve gate for local dev.

#### 14.4b. Chain corroboration — how many voices decide the anchored root (NC-12)

The anchored root is the chain fact that decides WHICH BYTES A USER IS SERVED, so NC-12's
"agreement across several concurrently-queried untrusted sources" applies to it directly. This
section states exactly how much corroboration the node performs, and — as precisely — how much it
does not. A SPEC that implied more than the code performs would be worse than one that admits the
gap.

**The endpoints.** The node resolves the anchored root from the coinset-protocol endpoints named by
`DIG_NODE_CHAIN_ENDPOINTS` (a comma-separated list). When that is unset, `DIG_NODE_COINSET` names a
single endpoint; when neither is set the node uses `https://api.coinset.org`. An unparseable entry
is DROPPED, never defaulted — a typo MUST NOT be able to masquerade as an additional source.

**Independence is derived from REACH.** Two endpoints are ONE voice whenever their resolved address
sets intersect, and the relation is transitive. Independence is NOT derived from an endpoint's type,
its URL, or its host name: a CNAME costs an attacker nothing, and a "quorum" satisfied by two names
for one machine is the defect this rule exists to prevent. With two or more endpoints configured, an
endpoint that resolves to no address contributes NO voice — the lookup is the evidence that it is a
separate machine, and a source that cannot be shown independent MUST NOT be counted as one.

A SINGLE configured endpoint is a voice whether or not its name resolves. Independence is a relation
BETWEEN endpoints, so with one endpoint there is nothing for a lookup to decide, and requiring one
would make name resolution a gate on READING: a resolver failure would deny a read the HTTP client
would have served, on the default install, over a path that performed no name resolution at all
before this rule existed. Failing closed is required when the CHAIN ANSWER is in doubt; a name
lookup is not that.

**The agreement rule, with two or more independent voices.** Every voice that answered MUST give the
SAME answer, and at least two MUST have answered; otherwise the resolution FAILS CLOSED and the pin
rejects the serve (§14.4, `-32005 ROOT_NOT_ANCHORED`). Specifically:

- One dissenting voice is a REFUSAL, never a repaired value. There is NO majority vote and no
  tie-break — a majority rule would hand the answer to whoever can field the most endpoints.
- Presence and absence are different answers: one source reporting a root while another reports no
  confirmed generation is a DISAGREEMENT, so a single source cannot conjure a store into being.
- A source that could not be REACHED is dropped rather than counted as dissent, because an outage
  and an attack demand opposite remedies. Dropping is still fail-closed: fewer answers means the
  agreement rule has less evidence, and fewer than two answers is a refusal.
- The rule covers all three resolution calls — the tip state, the bounded pinned-root verification,
  and lineage membership — because all three are consulted by the serve decision.

**A reached source that REJECTS a root vetoes the resolution; it is never outvoted.** This is stated
separately because the two verification calls answer a yes/no question and so have no value channel
in which to disagree. A source that is reached and says *"that root is not current"* MUST be
distinguished from one that could not be asked, and its rejection MUST refuse the whole resolution
regardless of how many other sources confirmed. A flat *k*-of-*N* threshold does NOT satisfy this
clause: under one, 2-of-3 and 2-of-10 are the same bar, so adding endpoints would not raise an
attacker's cost — and, with no attacker at all, three endpoints of which one is a generation behind
would serve stale content. **The bar rises with the number of REACHED sources, because every source
that answers can veto — not because more must agree.**

State that precisely, because the difference is the whole security property. A source can only veto
a resolution it was reached for; an UNREACHABLE source neither confirms nor vetoes, and adding an
endpoint therefore raises the bar only while that endpoint is answering. So an attacker who can
SILENCE a source — degrade its reachability rather than change its answer — removes that source's
veto, and a root two lagging endpoints still confirm is then served. Two consequences follow and
both are normative:

- A source that has ANSWERED a read MUST NOT be reclassified as unreachable on the strength of a
  later failed probe. Reachability is established BEFORE a verification, never re-tested after one:
  an endpoint that answered HAS been reached, and a subsequent failure describes its future rather
  than its past. The residual misclassification MUST run the other way — a chain that drops between
  the probe and the verification is recorded as a REJECTION, which refuses.
- The remedy available to an operator is the same one §14.4b already recommends and is stated here
  for a different reason: prefer **three or more** endpoints, so that silencing ONE still leaves a
  reached source able to veto.

**Latency and disclosure, both consequences of asking more than one source.** Endpoint independence
is recomputed per resolution, so the endpoint set is consulted on the content-serve request path.
Recomputing is NOT re-resolving: resolved address sets are CACHED for 60 seconds, so an ordinary read
costs a map lookup rather than a name lookup, and an independence verdict can be at most that stale.
A lookup that fails while a previously-resolved answer is still held (within 10 minutes) reuses that
answer rather than dropping the voice — a resolver blip is not evidence that an endpoint moved, and
silently changing the VOICE COUNT on that evidence would report a DNS hiccup as a corroboration
failure. Lookups that are performed are CONCURRENT and each is bounded (3 seconds); an endpoint that
exceeds it and has no cached answer counts as unreachable — the fail-closed direction. And resolving
discloses the STORE ID to every configured endpoint rather than to one. An operator adding endpoints
buys corroboration and widens that disclosure; both halves are real.

**ACCEPTED LIMITATION — the DEFAULT INSTALL resolves the anchored root from ONE third party.** With
fewer than two independent voices configured, the node answers from its single source, exactly as it
did before this rule existed. It does not claim corroboration in that state, and it does not refuse:
refusing would stop every unconfigured node serving any content at all, removing the surface on
which an operator could configure a second endpoint.

*Blast radius of that limitation:* a default install trusts `api.coinset.org` for the root every
content read is pinned to. A source that lied about it would redirect reads on every such install,
and the pin would fail closed against the WRONG root rather than the right one — indistinguishable,
from outside, from the store having moved on. It does NOT let that source forge content: bytes are
still accepted only because they verify against the merkle root (§21.2, §22.3). The remedy available
to an operator today is to name several independently-hosted endpoints.

*How many:* prefer **three or more**, not two. Two is the minimum the rule accepts and the most
fragile count it accepts, because with two ANY single source being unreachable drops the node to one
answer — below the corroboration floor — so every read refuses until it returns. A third endpoint is
what makes the guarantee survive one outage rather than converting one outage into a serve failure.
Note the veto is unconditional at every count: a third source raises availability, and it also gains
a third party able to refuse the read.

**ALSO SINGLE-SOURCED, and NOT corroborated (stated, not fixed).** These paths go to one endpoint
regardless of configuration: `coin_records_by_puzzle_hashes`, `coin_records_by_hints` and
`coin_records_by_parent` (the wallet's chain-fallback tier), mempool submission, the melt
confirmation, and the direct singleton walks the RPC surface performs. They are enumerated here so a
reader does not infer from the rule above that every chain fact is corroborated. By contrast
`peak_height`, `coin_record_by_id`, `coin_spend` and their cached variants ARE corroborated across
the node's own dialled Chia peers (§18).

### 14.4a. Per-path generation resolution (#2088) — serve TIP-AUTHORITATIVE, redirect only on a genuine tip miss (#2211)

A resource UNCHANGED since an earlier commit lives in an OLDER capsule whose own root ≠ the tip;
serving it at the tip (where its ciphertext is absent) folds to the constant-time decoy and reads as
a miss. The tip capsule's §13 `PublicManifest` records, per public path, the `latest_root` of the
generation that actually holds the file plus its `sha256_latest` leaf, so the serve CAN redirect to
that older generation — reporting the resolved generation as `X-Dig-Generation`.

**The serve is TIP-AUTHORITATIVE (fail-closed, #127/#2211 anti-rollback).** The `PublicManifest`
(§13) is an ADDITIVE `.dig` section that is NOT committed into the chain-anchored `current_root` and
NOT checked by the capsule anchor gate, so a malicious holder can serve a genuine, anchor-passing tip
capsule carrying a FORGED §13 whose per-path `latest_root`/`sha256_latest` redirect the read at other
content. To defeat this, the node MUST resolve the read in this order:

1. **Tip first, with NO §13 leaf binding.** Attempt the serve against the chain-anchored tip
   (`serve_root == tip`, `expected_leaf` absent), binding the bytes SOLELY by `proof.root == tip`.
   The tip's own `current_root` commits exactly the tip generation's leaves, so a path whose CURRENT
   version the tip holds is served from the tip — the §13 redirect is never consulted for it, and a
   §13 forged to name a genuine-but-superseded prior generation for that path CANNOT downgrade it.
2. **§13 redirect only on a genuine tip MISS, and only from a tip capsule that BACKS its committed
   root.** When the path is ABSENT from the tip capsule (its latest version legitimately lives in an
   older generation, so the tip serve folds to the decoy), the node consults the §13 entry and MAY
   redirect to that older `serve_root`. The redirect is honoured ONLY when BOTH hold:
   - **(a) the tip capsule genuinely backs its committed `current_root`.** The node re-derives the tip
     capsule and requires the merkle root recomputed from its own `MerkleNodes` to equal the committed
     `CurrentRoot`, AND that committed root to equal the chain-anchored tip. The capsule anchor gate
     compares only the 32-byte `CurrentRoot` HEADER against the chain, so it admits a capsule whose
     header still names the genuine tip while its data was tampered so a tip-committed path no longer
     folds to it — which would turn a forged tip MISS into a §13 redirect (a rollback). A tip capsule
     whose data does not fold to its committed tip is refused as a redirect source: its misses are
     untrustworthy, so the read stays a clean miss rather than a downgrade. (Implemented
     dig-node-locally by recomputing the tree via digstore's `verify_module_root`; the premise that "a
     tip MISS means the path is legitimately absent from the tip generation" is thereby ENFORCED, not
     assumed.)
   - **(b) `serve_root` is a GENUINE root in the store's authenticated on-chain singleton lineage** —
     the SAME lineage authority the §14.4 pin walks (`sync_datastore_with_history` membership). A root
     NOT in the lineage (fabricated, or unconfirmable) MUST NOT be served from.

   On this redirect path `expected_leaf` (= the tip manifest's `sha256_latest`) IS additionally
   enforced fail-closed on every tier so the older, non-chain-anchored capsule cannot substitute other
   bytes for the path. A non-Served tip outcome — a decoy MISS or an upstream ERROR — is deferred while
   a §13 redirect candidate remains, so a tip-pass upstream error never pre-empts a legitimate
   older-generation read (#2088).

- `serve_root` is NEVER client-derivable: a superseded root named in the REQUEST still fails
  `-32005` (§14.4) — only the node's own trusted tip manifest, cross-checked against the lineage, may
  redirect the read.
- **Case A is CLOSED (including against a tampered tip capsule).** A path whose CURRENT version the
  tip commits is served from the chain-anchored tip (forged redirect never reached), and a redirect is
  refused entirely when the tip capsule does not back its committed root — so a holder cannot forge a
  tip MISS to force the downgrade (#2211). **Case B remains OPEN:** a path whose current version
  genuinely lives in an OLDER generation than the one a forged §13 names — here the tip capsule
  legitimately backs its root and the path is genuinely absent from the tip, so the redirect is
  honoured and a §13 forged to name a genuine-but-superseded prior generation still rolls that path
  back, a downgrade BOUNDED to owner-committed content. Full closure requires a per-path current-state
  commitment the tip anchors (tracked in digstore #2203); `expected_leaf` binds the served bytes to
  *a* genuine lineage generation, it does NOT prove that generation is the path's canonical current one.
- **`X-Dig-Generation` is advisory, not trusted.** It is stamped from the §13 `generation_index`,
  which is additive/uncommitted and thus attacker-forgeable — a forged §13 can misreport the
  generation NUMBER even for a Case-A serve whose BYTES are the correct chain-anchored tip. The served
  bytes stay safe; only this cosmetic header can be spoofed. Closed by the same #2203 per-path
  commitment.
- No manifest / no entry (legacy `.dig`, private store, or a key outside the public surface) ⇒ serve at
  the tip with no leaf binding, byte-identical to the pre-#2088 behaviour.

### 14.5. Store-melt propagation (receive → on-chain-verify → delete → rebroadcast, #1316)

When a store's CHIP-0035 singleton is MELTED (the store-lifecycle delete), the deletion PROPAGATES
across the peer network so every holder stops hosting the store's `.dig` content and reclaims disk.
The wire is dig-gossip opcode **221** (`STORE_MELTED`, a `StoreMeltedAnnounce`: `store_id`,
advisory `melt_height`, `sender_peer_id`, BLS signature). It is a **public all-peers broadcast**
(Plumtree flood, Bulk priority), **§5.4-EXEMPT** from recipient-sealing: a store deletion is
public-by-nature and addressed to everyone, like L2 consensus gossip. It is mTLS-authenticated +
signed, never recipient-sealed.

**The on-chain melt proof is the SOLE delete authority (NC-9, fail-closed).** A node MUST NEVER delete
unless the chain POSITIVELY confirms the melt — a forged/replayed announcement, or a chain the node
cannot reach, deletes NOTHING. The announcement's signature is attribution/anti-spam ONLY (never delete
authority), and `melt_height` is an advisory hint the receiver never trusts on its face.

A store is confirmed MELTED only by walking its singleton lineage along real COIN PARENTAGE:

1. **Identity + minted.** The launcher coin whose `coin_id == store_id` MUST exist and be SPENT.
   `coin_id == store_id` is a 256-bit hash preimage an attacker cannot grind, so it pins the walk to
   the real store — never to a look-alike singleton that merely *curries* `launcher_id == store_id`,
   which IS forgeable. `spent` proves the store was ever minted (the launcher is spent exactly once,
   to create the eve singleton). An UNSPENT launcher is `Live`: not minted yet is the opposite of
   melted. This fact discriminates nothing on its own — it holds for every minted store — it anchors
   the walk's starting point.
2. **Walk forward by parentage.** At each hop, read the children of the current coin, DISCARD any
   returned coin whose `parent_coin_info` is not the current coin (the soundness argument is that
   parentage is fixed by which coin was actually spent — taking the server's word for membership of a
   "children of X" page would hand that argument back to whatever answered), and follow the
   single ODD-amount child (the singleton, whose amount is invariant across generations). An UNSPENT
   successor is `Live`. A spent coin with NO successor is `Melted` — the lineage terminated.

A coin's `parent_coin_info` is fixed by which coin was actually spent to create it, so **placing a
coin anywhere in this walk requires spending a generation of the store, which requires the owner's
authority.** The walk is unwritable by anyone but the owner.

Everything else is `Unknown` (fail-closed): any chain read that errors or times out — including
MID-WALK, which MUST NOT read as "the lineage ended here" — more than one odd child (ambiguous; never
guess which continues the lineage), an absent launcher coin, and exceeding the hop ceiling.

**Only a COMPLETELY EMPTY children page may conclude a melt, and never at hop 0.** Both halves are
load-bearing:

- *Hop 0.* A minted launcher always created the eve singleton, so an empty first hop means the answer
  is untrustworthy — a non-datastore launcher, or a chain-read implementation that does not implement
  the parent-ids query.
- *Completeness.* The children query honours a server-side limit, and truncation surfaces SPENT
  records first. Measured on coinset against the sibling hint query: no limit returns 349 records of
  which 243 are unspent, while `limit=5` returns 5 records of which **zero** are unspent. A truncated
  page that kept an even change coin but dropped the odd successor would read exactly like a
  terminated lineage. Requiring the page to be *entirely* empty is what asserts COMPLETENESS instead
  of trusting a page — truncation cannot turn a non-empty result set into an empty one short of a
  zero limit, which is never sent. Children present with no singleton among them is `Unknown`.

Two cheaper signals MUST NOT be used, both having shipped and been found unsound:

- **`anchored_root() == Ok(None)`** means *no confirmed generation* (fail-closed) everywhere else in
  the node, and is produced for a store that is **not minted yet**. A genuine melt does not even
  produce it — the lineage walk errors for a tip spent without a datastore child.
- **The `store_id` hint index.** A hint is an unauthenticated `CREATE_COIN` memo over an arbitrary
  32-byte value, so ANY party can place a record under ANY store's hint for the price of a dust coin.
  Measured against mainnet: of the 53 DataLayer stores, **30 live stores have a completely EMPTY
  `store_id` hint index** — their generations are not hinted to `store_id` at all — so for each of
  them one planted spent coin would make the index non-empty and entirely spent, indistinguishable
  from a terminated lineage. `get_coin_records_by_hint` is also truncatable, and truncation surfaces
  spent records first: the exact order that manufactures a false melt. The hint index MUST NOT carry
  a delete decision.

**Operator kill switch.** Store-melt propagation MUST be disableable at runtime via
`DIG_NODE_STORE_MELT` (default ON; only an explicit off-token — `off`/`disabled`/`0`/`false`/`no` — disables it), matching the
shape of `DIG_NODE_BACKFILL_ON_MISS`. This is the node's only path that irreversibly deletes content
in response to chain state, and it propagates, so a fault is correlated across holders rather than
isolated; an operator MUST be able to stop the deleting without downgrading the node. Disabling is
lossless — melted stores simply keep costing disk, and nothing else depends on melt propagation
having run.

**Conformance to real chain state (measured, not derived).** Across all 53 DataLayer launcher coins
on mainnet this rule yields 51 `Live` (deepest lineage 599 generations; 29 stores have their tip one
hop from the launcher) and 1 `Melted` — the one genuinely terminated store, which ends at hop 1. No
lineage produced an ambiguous fork. Because the walk costs one chain read per generation and the
receive path runs per inbound announcement, verdicts are memoised for a short TTL so a flood of
announcements for one held store cannot multiply into repeated walks; a stale verdict can only DELAY
a real melt, never cause a delete.

- **Holder path (the melting node).** For a store the node HOLDS whose singleton the chain confirms
  closed, and which is not already tombstoned: delete EVERY held generation (the audited cache-remove
  path — path-containment guarded, content-cache invalidating, idempotent), broadcast a signed
  `StoreMeltedAnnounce`, and tombstone the store. Live/Unknown ⇒ no-op (retried next tick).
- **Receiver path (a peer).** Per inbound opcode-221 frame, in strictly-increasing cost order (so an
  un-held flood is O(local) per message and can never amplify into chain work): (1) **held-check FIRST**
  — if the store is not held, drop with NO chain read, NO signature verification, NO rebroadcast; (2)
  **tombstone check** — a re-receipt drops with no chain read; (3) **NC-9 on-chain verify** — only a
  confirmed melt proceeds (fail-closed on Live/Unknown); (4) **delete + rebroadcast ONCE** — gated on a
  compare-and-set into the shared tombstone, so only the holding→deleted transition re-emits (excluding
  the sender).
- **Termination.** Each node broadcasts at most once per store (the CAS admits one transition), the
  tombstone is set-once (never cleared in-run), and dig-gossip's Plumtree seen-set dedups frames
  network-wide — so the epidemic quiesces after every holder has deleted once.
- **§5.1 preserved.** Deleting a CACHED `.dig` is safe: the on-chain anchor is permanent and this
  touches no history/anchor. Melt does not rewrite or break any older `.dig` format.

The receive/holder policy is unit-tested against spy seams (chain / cache / broadcast) with the eight
adversarial cases: forged-melt-for-live, chain-error-fail-closed, genuine-melt (delete-all +
rebroadcast-once), never-held (no chain call), already-tombstoned, verify-cost DoS (held-check before
chain), multi-node convergence-terminates, and holder fail-closed on transient error. The chain-fact →
verdict mapping is separately tested against the real chain-read trait with a crafted lineage, whose
mock PANICS if either hint query is touched: a terminated lineage is the ONLY shape that yields
`Melted`; an unspent tip at 1/2/7/60 hops, an unspent launcher, an absent launcher, an empty hop 0, an
even-amount child, an ambiguous two-odd-child fork, a transport failure on the launcher read OR
mid-walk, and an endless lineage all resolve to `Live` or `Unknown`. The composition that broke the
previous design — an empty hint index plus one planted spent coin — is covered explicitly and asserts
`Live`.

---

## 15. FFI — dig-runtime C-ABI (in-process host)

`dig-runtime` is a Cargo `cdylib` (`dig_runtime`, e.g. `dig_runtime.dll` shipped beside the browser
executable) exposing three C-ABI surfaces the DIG Browser links directly IN-PROCESS — no loopback
server, no socket, no `dig-node` sidecar:

- the **built-in wallet** (`dig_wallet_rpc`, §16) — the browser's reason to load the DLL;
- the **read-crypto** (`dig_read_verify_decrypt`, §15.1) — the digstore `.dig` verify+decrypt, the SAME
  `digstore-core` Rust the webpage `dig-client-wasm` wraps (ONE impl, two bindings: native FFI for the
  native browser, wasm for webpages — the browser NEVER uses wasm);
- the **full node RPC** (`dig_rpc`) — the SAME `dig_node_core::handle_rpc` dispatch the OS-service
  binary runs, retained for consumers that want an in-process node.

The runtime has TWO start modes, fixed by whichever `dig_runtime_start*` runs FIRST (idempotent
`OnceLock`):

- **wallet-only** (`dig_runtime_start_wallet`) — brings up the wallet host (§16) + tokio runtime with
  NO node engine (no P2P, no cache, no `dig_rpc` dispatch). This is the DIG Browser's mode: it links the
  wallet + read-crypto FFI and resolves `chia://`/`dig://` content from an EXTERNAL dig-node over RPC
  (the §5.3 ladder), running no in-process node.
- **full** (`dig_runtime_start`, or lazily on the first `dig_rpc`/`dig_wallet_rpc`) — builds the node
  engine + wallet host, for non-browser consumers that want an in-process node.

The C-ABI exports (all `#[no_mangle] extern "C"`, and panic-safe — a panic is caught and never crosses
the FFI boundary):

| Export | Signature | Behavior |
|---|---|---|
| `dig_runtime_start` | `void dig_runtime_start(void)` | Initialize the runtime FULLY: build the node engine + tokio runtime, load the §21.9 identity, prepare the cache, and start the wallet host. Idempotent; the FIRST `dig_runtime_start*` call fixes the mode. |
| `dig_runtime_start_wallet` | `void dig_runtime_start_wallet(void)` | Initialize the runtime WALLET-ONLY: bring up the wallet host + tokio runtime with NO node engine (no P2P/cache/`dig_rpc`). What the DIG Browser calls at startup. Idempotent; the FIRST `dig_runtime_start*` call fixes the mode. |
| `dig_rpc` | `char* dig_rpc(const char* request_json)` | Execute ONE DIG JSON-RPC request in-process and return the JSON-RPC response text. In WALLET-ONLY mode there is no node engine, so it returns a well-formed JSON-RPC error (`code -32000`, "node engine not available: dig-runtime started wallet-only") rather than spinning one up. Returns NULL only on a null/invalid input pointer or allocation failure. |
| `dig_wallet_rpc` | `char* dig_wallet_rpc(const char* origin, const char* request_json)` | Execute ONE wallet request (§16) for the calling page's web origin and return a JSON ENVELOPE `{"status": <u16>, "body": <raw JSON>}`, where `status` is the HTTP-equivalent status (200 ok / 202 pending / 403 not-approved / 4xx–5xx error) and `body` is the dispatch's JSON body embedded as RAW JSON (never a double-encoded string). Present in BOTH start modes. A null pointer or invalid UTF-8 in either argument yields a well-formed error envelope, never undefined behavior. |
| `dig_free` | `void dig_free(char* ptr)` | Free a string previously returned by `dig_rpc`/`dig_wallet_rpc`. NULL is ignored. |

- **String ownership.** `request_json` and `origin` are NUL-terminated UTF-8 strings OWNED BY THE
  CALLER for the duration of the call. Each non-NULL return value is a newly-allocated NUL-terminated
  UTF-8 string OWNED BY THE LIBRARY; the caller MUST return it to `dig_free` EXACTLY ONCE. Passing any
  other pointer to `dig_free`, or freeing twice, is undefined behavior.
- **Threading.** `dig_rpc` and `dig_wallet_rpc` BLOCK until the request completes on the shared runtime,
  so callers MUST invoke them from a thread allowed to block (e.g. a `base::MayBlock` task), NEVER the
  browser UI/IO thread. Concurrent calls are safe.
- **Shared state.** `dig_wallet_rpc` runs the SAME `dig_wallet::wallet_dispatch` the loopback
  `/api/wc/request` handler runs, against the SAME process-global wallet state — so the per-origin
  approval gate, the unlocked session, and the signer source are shared between the FFI path and the
  loopback wallet UI. The `origin` argument is supplied first-hand by the browser and is therefore
  UNSPOOFABLE (unlike a header a page could forge); the approval gate (§16) keys on it.

### 15.1. Read-crypto FFI — dig_read_verify_decrypt

The browser is NATIVE, so it verifies + decrypts served `.dig` content by calling the `digstore-core`
read-crypto Rust DIRECTLY over this C-ABI — NOT wasm (wasm is ONLY for webpages: hub / extension / SDK).
It is the SAME `digstore-core` crypto the webpage `dig-client-wasm` wraps as `decryptResource`, so a
native browser read and a webpage read derive the IDENTICAL key and enforce the IDENTICAL proof — ONE
Rust impl, two bindings. This call needs NO runtime and NO node engine: it is pure crypto over bytes the
caller already fetched from an external node (§5.3), so it works whether or not a `dig_runtime_start*`
has run.

| Export | Signature | Behavior |
|---|---|---|
| `dig_read_verify_decrypt` | `int32_t dig_read_verify_decrypt(const char* store_id_hex, const char* resource_key, const uint8_t* ciphertext, size_t ciphertext_len, const char* proof_b64, const char* trusted_root_hex, const char* salt_hex, const uint32_t* chunk_lens, size_t chunk_lens_len, uint8_t** out_ptr, size_t* out_len)` | Verify the served `ciphertext`'s Merkle inclusion against the chain-anchored `trusted_root_hex`, THEN AES-256-GCM-SIV-decrypt it — fail-closed (verify gates decrypt). On success returns `DIG_READ_OK` and writes a heap plaintext buffer to `*out_ptr`/`*out_len`; on ANY failure returns a `DIG_READ_*` code and leaves `*out_ptr`/`*out_len` null/0 (nothing to free). |
| `dig_bytes_free` | `void dig_bytes_free(uint8_t* ptr, size_t len)` | Free a plaintext buffer returned by `dig_read_verify_decrypt`. The `(ptr, len)` pair MUST be exactly one success's output. NULL is ignored. |

- **Inputs.** `store_id_hex` and `trusted_root_hex` are 64-hex (required). `resource_key` is the
  resource path (required; EMPTY resolves to the §8.5 default view `index.html`). `ciphertext` is the
  plain concatenation of the per-chunk ciphertexts (`ciphertext_len == 0` allowed with a null pointer).
  `proof_b64` is the base64 `X-Dig-Inclusion-Proof` header wire form (the Chia streamable `MerkleProof`
  codec). `salt_hex` is the 64-hex private-store secret salt, or NULL/empty for a PUBLIC store.
  `chunk_lens` are the per-chunk CIPHERTEXT byte lengths in order (NULL/0 ⇒ a single chunk) and MUST sum
  to `ciphertext_len`.
- **Status codes.** `DIG_READ_OK = 0`; `DIG_READ_BAD_INPUT = 1` (malformed argument — bad hex/base64,
  or `chunk_lens` not summing to `ciphertext_len`); `DIG_READ_VERIFY_FAILED = 2` (the served bytes'
  proof does NOT chain to the chain-anchored root — a tampered chunk or a decoy/wrong-store response);
  `DIG_READ_DECRYPT_FAILED = 3` (AES-256-GCM-SIV tag failure — a wrong key/salt or tampered ciphertext);
  `DIG_READ_INTERNAL = 4` (a caught panic or allocation failure). Every failure is fail-closed.
- **Buffer ownership.** The `out_ptr` buffer is OWNED BY THE LIBRARY; the caller MUST return it to
  `dig_bytes_free` EXACTLY ONCE with the matching `out_len`. This is a DISTINCT allocator discipline from
  the `dig_free` C-string path — never cross the two (a `dig_read_verify_decrypt` buffer to `dig_free`,
  or a `dig_rpc` string to `dig_bytes_free`, is undefined behavior).

---

## 16. Built-in wallet host — dig-wallet

`dig-wallet` is the DIG Browser's built-in Chia wallet host: a loopback `axum` server bound
`127.0.0.1:<DIG_WALLET_PORT>` (default `9777`) serving the wallet UI and a dapp-facing JSON-RPC
surface. That surface is a ROUTER, not a signer: every key/sign method is forwarded to the user's
Sage wallet over the WalletConnect delegate bridge, and NO signing happens in this process, which
holds no user key (§908). In the native browser it ALSO runs in-process via the §15 FFI
(`dig_wallet_rpc`), sharing one process-global wallet state with the loopback UI.

`DIG_WALLET_PORT` is read ONLY by `dig_wallet::run` — that is, by the DIG Browser runtime and by the
standalone `dig-wallet` binary. The `dig-node` binary NEVER starts a wallet host, so the variable is
INERT there and nothing binds the port; a `dig-node` run that finds it set says so on start-up.

Likewise `LOCALAPPDATA` relocates only the wallet's OWN artifacts — `DigWallet/seed.bin`,
`wallet.meta.json` and `DigNode/device/device.key`, which resolve env-first. It does NOT relocate the
node's cache, `config.json`, or the `wallet.sqlite` coin replica, which resolve through the OS
known-folder API; `DIG_NODE_CACHE` is the variable that moves those. A `dig-node` start-up that
resolves the two roots differently MUST WARN, naming both resolved roots.

It MUST additionally REFUSE to mint a new seed (writing nothing) when, and ONLY when, all three of
the following hold: `LOCALAPPDATA` is set to a root other than the node's own, no seed exists yet,
and `DIG_NODE_CACHE` is unset. Roots MUST be compared ignoring trailing separators, and ignoring
case on Windows, so a host whose environment and known-folder result differ only in spelling is NOT
a split.

Every other divergence MUST proceed and warn only. In particular, roots that diverge with NO
override — the wallet's env-first resolver falling back to the working directory while the node's
falls through the platform's passwd entry, which is what a service unit with no `HOME=` produces —
MUST mint normally: there is no override to undo, `DIG_NODE_CACHE` would not address it, and
refusing would leave such an install permanently without a wallet. The warning on that path MUST NOT
prescribe `DIG_NODE_CACHE`, because setting it changes nothing an operator would observe.

### 16.1. Method surface + dispatch

The advertised dapp JSON-RPC method catalogue is the crate's `WC_METHOD_CATALOGUE` — the single source
of truth (a drift test enforces that every advertised method has a real dispatch arm). Dispatch is a
`match` on the method-name string in `wallet_dispatch` → `wc_dispatch`, reached identically from the
loopback `/api/wc/request` handler and the §15 FFI. The surface groups as:

- **CHIP-0002 handshake/introspection** — `chip0002_chainId`, `chip0002_connect`, `chip0002_getMethods`
  (introspection returns the full catalogue).
- **CHIP-0002 keys + signing** — `chip0002_getPublicKeys`, `chip0002_signMessage`,
  `chip0002_signCoinSpends`, `chip0002_getAssetBalance`, `chip0002_getAssetCoins`.
- **`chia_*` wallet surface** — address + sign (`chia_getAddress`, `chia_signMessageByAddress`),
  payments (`chia_send`), history (`chia_getTransactions`), NFTs (`chia_getNfts`, `chia_transferNft`,
  `chia_mintNft`, `chia_bulkMintNfts`), DIDs (`chia_getDids`, `chia_createDidWallet`, `chia_transferDid`),
  and offers (`chia_getOfferSummary`, `chia_createOffer`, `chia_takeOffer`, `chia_cancelOffer`).
- **CHIP-0035 store lifecycle** — `chia_mintStore`, `chia_advanceStore`, `chia_meltStore`,
  `chia_setStoreDelegation`, `chia_setStoreOwnership`.
- **`dig_*` advanced coin types** — clawback (`dig_clawbackSend`/`Claim`/`Recover`), options
  (`dig_optionCreate`), streams (`dig_streamCreate`/`Claim`/`Clawback`), vaults (`dig_vaultCreate`), and
  verifiable credentials (`dig_vcVerify`).

A method that is not in the advertised catalogue (including deliberately-unsupported advanced methods)
MUST return `501 Not Implemented` with an explanatory message — an HONEST "unsupported in this build",
never a fabricated result.

### 16.2. Authorization — two independent gates

A spend reaches mainnet ONLY when BOTH gates pass:

1. **Per-origin consent gate.** The caller's web origin — the unspoofable HTTP `Origin` header on the
   loopback path, or the first-hand origin over FFI (§15) — is checked: public methods
   (`chip0002_chainId`/`getMethods`) need no approval; `chip0002_connect` from an unapproved origin is
   PARKED as pending (`202`); any key/sign method from an unapproved origin is FORBIDDEN (`403`); an
   approved origin proceeds. Approvals persist to `connections.json`.
2. **Sage decides whether to sign.** An approved origin's key/sign request is FORWARDED to the user's
   Sage wallet over the WalletConnect requester session; this process signs nothing and broadcasts
   nothing (§18.20). The prior local broadcast gate (`DIG_WALLET_ALLOW_BROADCAST`, dry-run by default)
   went with the local signer it gated — there is no longer a bundle built here for it to withhold.
   Sage's own confirmation UI is now the second gate, which is the point: the gate lives with the key.

### 16.3. Secret custody

Seed-reveal / private-key-export class methods (`export`, `exportMnemonic`, `chip0002_export`,
`chia_export`, `getMnemonic`, `getSecretKeys`, `getPrivateKey(s)`, `revealSeed`) are HARD-BLOCKED from
the dapp dispatch surface — they are absent from dispatch (fall to `501`) and are refused before any
forward to Sage, so a Sage that implemented one could not be reached through this surface. The refusal
is indistinguishable on the wire from any other unknown method, so the set of export spellings cannot be
probed.

There is no local reveal route either: `POST /api/export` was removed with the rest of the custody plane
(§18.20, dig-node#327). A seed an earlier build already wrote is recovered OFFLINE with `dign wallet
export-seed`, which has no network surface at all.

### 16.4. Unattended wallet bootstrap (`autoseed`)

On EVERY start — first install, post-update, and every ordinary boot — the node MUST determine whether
its OPERATOR seed exists and MUST mint one when there is definitely none. The path requires no user
interaction: no prompt, no password.

This seed is the node's OWN machine identity (`DIGOP1`/`DIGVK1`, sealed under a device key), NOT a user
wallet, and §18.20 does not retire it: a user's spend key never enters the node, and this key never
leaves it. The two are separate concerns that happen to share an at-rest primitive, and conflating them
would break the node's auth in the name of tightening custody it does not hold.

**At-rest format.** An auto-created seed is sealed in a `dig_keystore::opaque` `DIGOP1` container
(AES-256-GCM, Argon2id) under a 32-byte CSPRNG **device key**. An imported seed is sealed under the
user's password. Both are the same container; only the key differs. An existing user-password seed MUST
be opened with the user's password exactly as before and MUST NEVER be re-sealed to the device key.
Auto-creation applies only when there is no seed at all. The phrase is 24 words from
`digstore_chain::seed::generate_mnemonic`, over the canonical `entropy → mnemonic → to_seed("")`
expansion.

**File layout.** All three files are created owner-only (`0600` at open time on Unix; an explicit
protected `D:P(A;;FA;;;<user>)` DACL on Windows, never the ACL inherited from `%LOCALAPPDATA%`):

| Path | Contents |
|---|---|
| `<wallet_dir>/seed.bin` | the sealed mnemonic — format unchanged |
| `<device_dir>/device.key` | 32 raw CSPRNG bytes, no header |
| `<wallet_dir>/wallet.meta.json` | `origin`, `created_at` (RFC 3339), `ever_funded` |

`<device_dir>` is `<user_base>/DigNode/device/` — a **SIBLING** of `<wallet_dir>`
(`<user_base>/DigWallet/`), never a child. **That separation IS the partial-exfiltration boundary and
MUST NOT be collapsed.** Placing the key inside the wallet directory degrades the seal to a
well-known-password seal: a file that still carries the `DIGOP1` magic, still passes any "encrypted at
rest" check, and protects nothing, because the artifact that opens it travels with every copy.

**The security boundary, stated as a limit.** The device key confers **no** protection against an
attacker executing code as the node's user, nor against an attacker holding the whole disk — both files
sit on one volume. It protects the seed against copies of the wallet directory made without the device
key: backups, snapshots, image layers, sync clients, and diagnostic bundles. No sentence in this repo
may describe it as protecting the seed from local compromise.

**Relationship to NC-2 / NC-3.** NC-2 ("at-rest data is encrypted to the user's keypair") cannot apply
to this artifact, for a structural reason rather than an effort one: **the seed IS the root key**, so
there is nothing to encrypt it to until it exists. This is the bootstrap case that necessarily precedes
the identity, not an exemption — the same crate, the same container and the same primitives are used,
under the strongest key available before an identity exists, and the artifact converges onto NC-2's
shape by re-seal in place once a user password exists. NC-3 is satisfied in full: the files live under
the per-user, non-roaming base directory and are genuinely encrypted at rest.

**Failure behaviour — every arm fails closed, and none of them writes.** `try_exists()` is used
throughout; `Path::exists()` MUST NOT appear on this path, because it reports a metadata failure as a
plain "absent" and would convert a transient read error into an overwritten wallet.

| # | Condition | Behaviour |
|---|---|---|
| 1 | the seed path's existence cannot be determined | refuse; create nothing, including the device key |
| 2 | seed present, device key absent or unreadable | **never mint a key**; leave both files untouched. Classified by `origin`: `auto`/`auto-acknowledged` → `Orphaned`; `imported` or an absent sidecar → `Locked` |
| 3 | seed present and opens under the device key | normal start; nothing written |
| 4 | seed present and does not open | leave it exactly as found; a file that fails to decrypt is still evidence of a wallet |
| 5 | both absent | create the device key, then the seed, both `create_new`; a lost race adopts the winner and deletes nothing |
| 6 | permissions cannot be established | remove the partial file and refuse; a secret is never left at an unproven path |

There is deliberately **no fallback**. If the device key cannot be established the node runs
**wallet-less and says so**; it does not degrade to plaintext and it does not prompt. A bootstrap
failure is never fatal to the node — serving content has never required a wallet.

**Origin marking and the funded latch.** `origin` is one of `auto` (machine-created, the 24 words never
shown to a human), `auto-acknowledged` (auto-created and since revealed to the user), or `imported`.
`ever_funded` is a **monotonic latch** set on the first observation of a non-zero balance and NEVER
cleared; `latch_ever_funded` persists it and is idempotent. A wallet may be described as disposable
ONLY when `origin` is `auto` AND `ever_funded` is false. An absent or unparsable `wallet.meta.json`
MUST answer "not disposable". A momentarily-zero or unreadable balance is not evidence a wallet never
mattered, which is why this is a stored latch rather than a live predicate.

**The observation point.** The mirror pass observes the operator wallet's own balance on a timer and
classifies each reading before latching. The classification has THREE outcomes, not two, and the
distinction is normative: a non-zero figure latches from EITHER tier, so a stale replica or a chain
fallback answer showing money latches immediately; a CURRENT zero from an authoritative tier is real
evidence of emptiness and does NOT latch; and an unreadable or non-current zero says nothing and
latches nothing. That last case DEFERS rather than latching, because every node is in it for the
first seconds of its life — latching there would make the disposable predicate vacuously false for
every wallet in the ecosystem, and the latch is monotonic, so deferring can never settle into
describing a funded wallet as disposable.

**The device key and the wallet directory are a COUPLED PAIR.** `<device_dir>` and `<wallet_dir>` are
meaningful only together: neither opens the seed alone. Any operation that removes one MUST remove or
preserve both — an uninstall-with-data path that deletes `<wallet_dir>` and leaves `<device_dir>`
strands a useless key, and one that deletes `<device_dir>` alone **permanently destroys an
auto-created wallet whose phrase has never been shown to anyone** (see the recovery gap below). The
two paths are currently defined locally in `crates/dig-wallet/src/autoseed.rs` and are published by no
shared constant; a `dig-constants` home for the pair is the correct fix and is not done here.

**The recovery gap.** An `origin: auto` wallet's recovery phrase has never been displayed to anyone, so
loss of the disk is loss of the funds — inherent to the no-interaction mandate. Clients MUST surface a
phrase-reveal/replace affordance for such a wallet; `auto-acknowledged` records that it was shown.

**Secret hygiene.** The mnemonic, the seed, the device key and any derivative MUST NEVER reach a
`tracing` field or message. `DeviceKey` implements no `Debug`, `Display` or `Serialize`.

---

## 17. Outgoing-bandwidth throttle and redirect-on-saturation

The standalone node's P2P content engine (`crate::download`, #164/#165) redirects a caller to another
holder when this node does NOT hold the requested content ("redirect-on-miss," `-32008`
`CONTENT_REDIRECT`, §10). This section extends that mechanism from "not held" to "held, but serving it
now would exceed this node's configured outgoing-bandwidth budget."

17.1. **Configuration.** `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC` (§3.2) sets a bytes/second cap on the
node's outgoing serve traffic. `0`, unset, or unparsable is UNLIMITED — the throttle is opt-in; an
unconfigured node's serve path is byte-identical to before this feature. The cap is resolved once at
node construction (`bandwidth::OutgoingThrottle::from_env`).

17.2. **Accounting.** The throttle tracks bytes served in a fixed 1-second window (`served_bytes`
against `window_start`), rolling to a fresh window once a full second has elapsed. Before writing a
chunk the serve path asks whether `served_bytes + this_chunk` would exceed the cap
(`OutgoingThrottle::would_exceed`) — a peek, not a reservation; on any serve (including the graceful
fallback, §17.4) it then records the bytes actually sent (`OutgoingThrottle::record_served`).

17.3. **Serve-path integration.** The check runs on every surface that returns resource bytes this
node already holds locally, immediately before the bytes would be written:

- `dig.getContent`'s LOCAL-FIRST serve (a cold cache hit and the post-§21-sync hit alike);
- `dig.fetchRange`'s local frame serve;
- the mTLS peer range-stream (`stream_range`) — the busiest outgoing surface, since multi-source
  downloaders fan byte-ranges across it.

When the check trips, the node resolves alternate holders via the DHT
(`download::NodeContent::find_providers`, self excluded) and, if any exist, answers with the SAME
`CONTENT_REDIRECT` error object shape redirect-on-miss uses
(`download::redirect_error_object` — `error.data.redirect.{content,providers,redirect_depth,max_redirects}`)
instead of writing the over-budget bytes. `providers[].addresses` follow the candidate ordering the DHT
returns, which is IPv6-first (§5.2 — dig-dht orders reflexive/candidate addresses IPv6-first; the
throttle does not reorder them).

17.4. **Hop budget (shared with redirect-on-miss).** A bandwidth-redirect consumes the SAME
`redirect_depth`/`REDIRECT_HOP_CAP` budget as a miss-redirect (§10's `-32008` entry): the caller echoes
the depth a redirect served it, and a request already at the hop cap is served locally rather than
redirected again, so saturated nodes can never bounce a caller in a loop regardless of which mechanism
(miss or bandwidth) issued the prior redirects.

17.5. **Graceful fallback — never fail closed.** The node serves the request normally (recording the
bytes against the throttle) whenever a redirect is not possible: under budget; no P2P content engine is
attached (the in-process FFI/DIG-Browser path never redirects, having no peer network to redirect to);
the hop budget is exhausted; or the DHT knows of no alternate holder. The throttle changes WHERE a
request is served from when it can, never WHETHER it is served — an over-budget request with no known
alternate still goes out rather than being dropped or erroring.

## 18. Sage-parity wallet RPC — direct-peer sync, local wallet DB, fallback tier

This section specifies the dig-node's **Sage-parity wallet RPC**: a byte-compatible replica of the
[Sage](https://github.com/xch-dev/sage) wallet RPC surface (`endpoints.json`, **pinned v0.12.11**,
commit `a84d7dfc`) backed by a direct-peer chain sync into a local wallet database, with a
`chia-query`/coinset fallback tier. A Sage RPC client can point at the dig-node interchangeably with
Sage. It is a new surface, additive to and DISTINCT from the built-in wallet host (§16), the read/control
JSON-RPC (§5/§7), and the CHIP-0002 `window.chia` dapp responder. It lives in the `dig-wallet` crate
(`crate::sage`). #215 shipped the READ + sync foundation; #216 added NFT/DID/CAT reconstruction (§18.11)
and the send/spend method group (§18.9); #218 added the offer suite + DID/NFT mint & transfer (§18.9a);
#205 PR4 added the `SyncEvent` stream (§18.14), the option-contract suite (§18.15), record-update
actions + the theme store (§18.16), network/peer settings (§18.17), the dig-keystore seed migration
(§18.18), and the generated-OpenAPI conformance vector (§18.19) — completing the served method surface
to 75 of the 100 Sage `endpoints.json` methods (the remaining 25 are secret-touching, gated per §18.10,
or Sage-desktop-only per design Part F MAY/N-A, e.g. `delete_database`/`perform_database_maintenance`).

18.1. **Transport — one method surface, two transports.** Byte-compatibility with Sage is required at
the application layer (method names + JSON request/response shapes); the transport is adapted per client
class. Both listeners dispatch the SAME handler set (`WalletBackend::dispatch`), so their bodies are
byte-identical by construction:

- **mTLS `9776`** (default; configurable). `POST /{method}` over TLS with Sage's shared-self-signed-cert
  MUTUAL-TLS model: the server accepts a client cert iff its DER is byte-identical to the server's own
  cert (a local-possession auth model — whoever can read the cert+key is authorized). Loopback only.
- **Plain-HTTP + CORS** (browser mirror). A browser/MV3 extension cannot present a client cert, so the
  identical surface is served over the loopback plain-HTTP transport with permissive CORS. Loopback only.

On the shipped `dig-node` binary this surface IS served (#368): the service bring-up assembles ONE live
`WalletBackend` (`sage::service::WalletService` — the wallet DB + a graceful fallback tier + a shared
`EventBus` + the node custody) and (a) integrates the browser mirror onto the SAME loopback service router
as `POST /{method}` on the default port `9778` — the exact base the extension's `node-wallet` client
targets — with the wallet authz gate (§7.12) applied, and (b) brings up the mTLS `9776` sibling listener
(best-effort, non-fatal) for node-class/Sage-drop-in parity. The parity port MUST NOT be Sage's own RPC
port (`9257`): dig-node is an auto-starting OS service and Sage is a desktop app, so binding it makes the
two race for one socket and a Sage client that reaches this mTLS listener is rejected at the handshake.
A bind failure remains non-fatal, and MUST be logged and reported on `control.status`
(`wallet_mtls`: `listening` | `unavailable` | `not_started`) — never silently. The bidirectional `/ws` transport (§4.8) also
dispatches to this same backend. Wallet methods are NEVER relayed to the upstream gateway.

18.2. **Request/response model.** Every endpoint is `POST /{endpoint}` where `{endpoint}` is the exact
snake_case method name. There is NO JSON-RPC envelope, NO batching — the path IS the method. Request body
= the method's request struct as a single JSON object (an empty body is treated as `{}`). Success →
`200 OK` with the response struct as JSON (`content-type: application/json`). Error → a non-200 status
with the error message as a **plain-text** body (NOT a JSON error object), reproducing Sage's model.

18.3. **Wire types (byte-parity invariants).** The request/response/record types match `sage-api`
byte-for-byte:

- **`Amount`** — an untagged enum serializing as a JSON **number** when `<= 9_007_199_254_740_991`
  (`MAX_JS_SAFE_INTEGER`), else a JSON **string**; deserializes from either. This exact threshold MUST be
  reproduced (JS clients depend on it). Amounts are in the asset's smallest unit (mojos for XCH).
- **Casing** — struct fields are snake_case (Rust idents already are; no `rename_all` on structs); enums
  carry `#[serde(rename_all = "snake_case")]`.
- **Optional fields** — `Option<T>` serializes as `null` when `None` (Sage does NOT omit them); field
  order equals declaration order.

18.4. **Error model.** `ErrorKind` → HTTP status: `api` → `400`, `not_found` → `404`, `unauthorized` →
`401`, `unavailable` → `503`, `wallet`/`internal` → `500`. An unknown/unsupported method is `404`; a
malformed request body is `400`.

`unavailable` is distinct from `internal` and the distinction is normative: `internal` means the node
tried and something broke, while `unavailable` means the node is working correctly and is NOT ENTITLED
to the answer. A read that cannot be honestly answered MUST return `unavailable`; it MUST NOT return a
figure, because the only figure available to it is `0` and the caller cannot distinguish that from
holding nothing.

18.5. **Local wallet database (SQLite).** The sync loop persists the wallet's chain state to a local
SQLite database (via `sqlx`), mirroring `sage-wallet`'s relational store: coins/CATs/derivations (and
NFT/DID/collection tables, plus an `offers` table for imported/built offers, #218) keyed by the wallet's
hardened AND unhardened HD puzzle hashes + CAT hints, plus the synced peak height. SQLite (NOT RocksDB): the workload is relational, multi-index, query-rich
and small (one wallet). Indexes on `puzzle_hash`, `asset_id`, a PARTIAL index on unspent
(`spent_height IS NULL`), and `created_height`; WAL enabled. Amounts are stored as decimal TEXT (full
`u64`/`u128` range, no `i64` overflow). This DB is the source of truth for a SYNCED wallet's data.

18.6. **Direct-peer sync (primary path).** Wallet chain data is obtained by connecting directly to Chia
full-node peers over the light-wallet protocol on `chia-wallet-sdk 0.36` `Peer` (`NodeType::Wallet`,
protocol `0.0.37`, the four DNS introducers, multi-peer, IPv6-first per §5.2), exactly as Sage does — NOT
via coinset for the wallet-data path. The node subscribes the wallet's puzzle hashes (BOTH hardened and
unhardened + CAT hints) with `request_puzzle_state(subscribe = true)`, applies the returned coin states,
then consumes `coin_state_update` pushes into the DB. A reorg (a `coin_state_update` whose `fork_height`
is below the current peak) rolls the DB back above the fork — coins created above it are deleted, coins
spent above it become unspent again — then applies the update's coin states and advances the peak.

18.6a. **The sync supervisor (the production call site).** A background supervisor owns the §18.6 loop's
lifecycle on every install: it dials a peer, catches up, consumes pushes, and reconnects with an
exponential 1s→60s jittered backoff that resets after a connection lasting at least 60 seconds. It holds
EXACTLY ONE subscription peer — the subscription is per-connection state, and concurrent peers would drive
interleaved reorg rollbacks into a DB with a single writer. A reconnect re-runs the catch-up from the
genesis challenge, because a fresh peer has no memory of the previous subscription. Sync is a chain READ
plus a write to the node's own replica, so it MUST NOT be gated on the live-broadcast (spend) flag.

The subscription set is the UNION of two sources, both mapped through the SAME
`StandardArgs::curry_tree_hash` derivation: the node's own custodied PUBLIC keys, and the public keys an
external client registered under §18.6f. It is re-read on every connect attempt AND — while a session is running with nothing subscribed — re-polled at
least every 5 seconds, so a wallet created after boot is picked up without a restart and without waiting
for the peer to drop. A newly non-empty set ends the peak-only session and reconnects immediately, since
the subscription is per-connection state. No seed is read and nothing on this path can sign (§908).

**A session MUST have a deadline on every wait, because a peer can go silent on a live socket.** Two
waits carry one:

- ONE puzzle-state round trip during a catch-up MUST complete within 60 seconds, or the catch-up fails
  and the peer is dropped and re-dialled. The bound is PER ROUND TRIP: a catch-up runs from genesis
  over many batches, so a total deadline tight enough to bound a batch would abort a healthy long sync
  and restart it from the beginning for ever.
- A catch-up as a WHOLE MUST also carry a total deadline, because a per-round-trip bound bounds one
  answer and not the sequence of them: a peer answering each round trip just inside 60 seconds
  satisfies it indefinitely. The total deadline MUST be generous — an hour, against catch-ups measured
  in tens of milliseconds — since the two errors are not symmetric: too loose merely leaves a
  pathological peer holding a session, whereas too tight produces a replica that never finishes. It
  MUST be a single budget and MUST NOT be selected by whether a catch-up is the first one: every
  catch-up runs from genesis, so the two describe the same work, and `initial_sync_complete` in
  particular MUST NOT be the discriminator because an accepted reorg clears it and an untrusted peer
  would then choose which budget applies.
- A catch-up MUST NOT disarm SHUTDOWN. It is the one long-running step in the session lifecycle, and
  a node that cannot be stopped while it runs is a defect independent of what the sync eventually
  does. Shutdown MUST end the catch-up promptly, without backing off or reconnecting on the way out.
- An AUTHORITATIVE subscribed session that holds the replica STILL for 90 seconds while the node's own
  Chia peers are observed to be strictly ahead of it MUST be ENDED, so the ordinary reconnect path
  dials a fresh peer. The node MUST log the reason with both heights, AND MUST log the RECOVERY when
  the replica advances again — a stall that is logged and a recovery that is not leaves the operator
  with a failure followed by silence, which is indistinguishable from the failure continuing. Stall
  detection is armed for authoritative sessions only: a `Discovered` session never advances the peak
  by design, and its exit is the re-corroboration timer instead.

Stall evidence MUST accumulate across sessions, not within one. Sessions end for many reasons, and a
clock that restarts at every session boundary can never reach the deadline while a replica stays
frozen — the detector would be present and unreachable.

**A session MUST NOT be held indefinitely.** One subscription session runs for at most 600 seconds and
is then retired, so a hostile or merely unlucky peer set cannot be held for the life of the process.
A retirement is a PLANNED end: it reconnects at once and MUST NOT advance the reconnect backoff. The
new session earns its write authority from a freshly drawn quorum like any other; a verdict MUST NOT
be carried across sessions.

**Rotation does NOT subsume the staleness detector, and MUST NOT be used to justify removing it.**
The two answer different questions on different timescales: rotation bounds how long a bad situation
can last, and detection is what makes it DIAGNOSABLE. A fast rotation would have hidden this defect
entirely — the replica would have recovered on its own every cycle, and nobody would ever have learned
that a session can go silent while the node reports `synced` for hours. A node that recovers silently
from a fault it cannot name has not fixed the fault.

The three session timescales form a deliberate ladder — 45s re-corroboration (a session that CANNOT
write) < 90s stall (a session that has STOPPED writing) < 600s rotation (a session that is merely
HELD). Each governs a different concern; collapsing any two silently retires one of them.

Ending a session on a stall does NOT lower the corroboration bar (§18.6d): the reconnect draws an
independent sample and re-runs the quorum exactly as any reconnect does. A stall MUST be declared only
on POSITIVE evidence — a replica that advanced, an unobservable height on either side, and a replica
merely level with its peers each reset the clock, because an unmeasured or level reading is not
evidence of a freeze. Without these deadlines a half-open connection parks the session for the life of
the process: a replica froze at height 9,142,861 while its peers announced 9,142,918 and the gap grew
without bound, reported throughout as `synced`.

18.6f. **Externally-registered addresses (the §908 install).** A node MAY be asked to FOLLOW addresses it
does not custody. `control.wallet.watch` registers G1 public keys, `control.wallet.unwatch` deregisters
them, and `control.wallet.watched` lists what is currently registered. All three are MUTATIONS and
therefore require authorization; none is an open read.

This exists because the correct install has no USER seed on the node at all (the node's own operator seed, §16.4, is machine custody, not the user's account): under §908 the user's account
lives in dig-app, so custody contributes zero puzzle hashes, §18.6a refuses a catch-up over the empty set,
and the replica's peak never advances. Registration is the only way such a node can watch its user's
coins.

**Invariant.** Registration MUST be persisted and MUST survive a restart, and `unwatch` MUST remove the
key from the set the supervisor reads AND from the persisted set — a deregistered address stops being
followed on both paths.

**Invariant.** The subscription set MUST be the UNION of custody's set and the registered set, never
either alone. Following a strict subset of the addresses the operator arranged under-reports a BALANCE,
which is a wrong number that presents as a working feature.

**Invariant.** A node with registered keys and no custody HAS a wallet enrolled: it MUST NOT report the
`no_wallet_enrolled` all-clear of §18.6b. Enrolment is sourced from custody's manifest OR a non-empty
registry, never from whether the address set happens to be non-empty.

**§908.** A public key is public. Registration conveys no seed and no signing capability; it aims the
node's chain subscriptions and nothing else.

**Privacy.** Following an address makes it observable to the node's Chia peers that this machine cares
about that address. This is already true of the node's own custodied addresses; registering an account
extends the same exposure to it. A client SHOULD state this where a user enrols an account.

**Invariant.** A catch-up MUST NOT run over an empty puzzle-hash set, and `initial_sync_complete` MUST NOT
be set as a result of one. `initial_sync` itself refuses with `NoPuzzleHashes`. An empty subscription is
answered "finished" immediately, so completing it would mark an un-queried DB authoritative under §18.7 and
report a funded wallet as empty. A node with no wallet therefore stays unsynced, and — where its only
peer is a discovered one — writes nothing at all.

**Invariant — the replica MUST answer only for addresses a sync actually COVERED on the address-scoped money
reads.** A completed sync MUST record the puzzle-hash SET it ran over, in the SAME write that marks the
replica authoritative, and an address-scoped money read (`balance_for_address` / `coins_for_address`;
`control.wallet.balance` / `control.wallet.coins`) MUST be served from the local replica only while that
recording CONTAINS the set the node currently follows. `initial_sync_complete` alone MUST NOT decide those
reads: that flag records THAT a sync finished, never WHICH addresses it covered, so a set that WIDENS after
a completed sync — an enrolment — would otherwise make the replica authoritative for an address it never
followed and answer a funded wallet `balance: 0, synced: true, source: "db"`.

The question MUST be asked as CONTAINMENT, not equality: a set that has NARROWED (an `unwatch`) is still
covered by the wider sync that ran over it, and invalidating on a narrowing forces a needless full resync.
Coverage MUST NOT be inferred from a second write ordered against the first: an enrolment persists before
any follow-up can run, and `watch` is idempotent, so an interrupted or failed invalidation would latch the
widened set permanently while the client's retry enrolled nothing and invalidated nothing. A missing
recording (a replica synced before this rule) covers NOTHING — reads fall to the chain tier, which answers
truthfully.

**Invariant — the IDENTITY-scoped reads MUST ask the same containment question about the CLIENT's scope.**
`get_sync_status` and `wallet_coins` are scoped to the puzzle hashes the connected client supplied at
`login`, which arrive per-connection and need not be followed by this node at all. Both MUST be served
from the local replica only while the recorded coverage CONTAINS that client scope, and MUST NOT route on
`initial_sync_complete` alone. Where the scope is NOT covered, `wallet_coins` MUST fall to the chain tier
and `get_sync_status` MUST report `synced_coins < total_coins` — never a complete, synced, zero view.

The scope MUST be the client's identity and MUST NOT be the node's followed set. A node under §908 holds
no custody and may hold no registrations, so its followed set is EMPTY and every recording trivially
contains it; routing the identity-scoped reads through that predicate would be vacuous and would serve an
uncovered client a synced zero exactly as before.

**Invariant.** A catch-up MUST NOT run over an UNCORROBORATED peer, and `initial_sync_complete` MUST NOT
be set as a result of one. `initial_sync` itself refuses with `UntrustedPeer`, and it decides on the
EFFECTIVE trust it is handed — which for a discovered peer is the trust resolved AFTER corroboration
(§18.6d), not its dial source. The check MUST remain at that floor rather than only in the caller: a
caller-side check is one refactor, or one reconnect after a hostile disconnect, away from gone.

A discovered peer that has NOT been corroborated runs as a WRITE-FREE session whatever the wallet holds:
it subscribes nothing and persists nothing. **A node whose attached session MAY NOT WRITE therefore MUST
NOT report `synced`, however long ago a catch-up completed.** `initial_sync_complete` is persistent and a
refused writer's frames — including the peak — are dropped before any DB write, so the replica falls
behind by an unbounded, invisible amount while the flag still says a catch-up finished. `synced` is
specified as caught up AND in a position to be kept current, and a node holding a connection it may not
trust is not in that position; it MUST report `syncing`. Corroboration MUST be attempted BEFORE the catch-up, so a peer
that fails it never has a window in which its answers are already landing.

**A refusal MUST expire.** Corroboration is decided ONCE per session, so an uncorroborated session MUST
be ENDED after `RECORROBORATE_AFTER` = **45 s** and reconnected, which re-runs the corroborator against a
freshly drawn sample. A refused session MUST NOT be held until the peer happens to disconnect: a healthy
peer never does, so a single non-elevating round would otherwise freeze the replica for the life of the
process while the chain moves on. The timer MUST NOT apply to an operator or corroborated session —
ending one discards a live per-connection subscription and forces a fresh catch-up from genesis.

**Bounded catch-up.** One catch-up MUST make at most 1,024 round trips and write at most 250,000 coin
states in total, and a response carrying `is_finished: false` MUST report a height strictly greater than
the previous response's, or the catch-up is abandoned. `is_finished` is a bit the peer chooses, so
without these a peer answering `false` at a constant height loops forever, growing `wallet.sqlite` on
every round trip.

18.6c. **The peer is untrusted, and a DISCOVERED peer is never authoritative.** The peer socket is
attacker-reachable: peer discovery tries `127.0.0.1:8444` before any introducer and the client does not
verify the server certificate, so an unprivileged co-resident process can become the node's chain source.

**The trust boundary.** A peer's authority is decided by HOW it was reached, never by anything it says:

* An **operator** peer is a `user_managed` row in the `peers` table — an address a human deliberately
  entered. It has full authority: it MAY run a catch-up, set `initial_sync_complete`, write coins, and
  drive a bounded rollback.
* A **discovered** peer (a DNS introducer answer, or the loopback probe) arrives with NO authority. On
  arrival it MUST NOT cause ANY write to `wallet.sqlite`: it MUST NOT write coins, MUST NOT roll the
  replica back, MUST NOT cause `initial_sync_complete` to become `true`, and MUST NOT move the replica
  peak in EITHER direction. Its entire contribution is LIVENESS: it counts toward the `subscription_peer_count`
  of §18.6b, which is an observation the node makes about its own socket rather than a claim the peer
  makes.

  The peak is named explicitly because it was once permitted, monotonically, on the reasoning that a
  too-high peak only makes a confirmation read more conservative. That reasoning is INVERTED: a
  confirmation count is `peak − created_height`, so a higher peak means MORE confirmations, and one frame
  at `u32::MAX` reads as ~4.29e9 confirmations for a spend that never landed — on the value
  `control.wallet.peak` exists to let a caller bound a claimed confirmation with. A monotonic rule also
  makes that value PERMANENT, because it refuses every honest peer's correction. An implementation MUST
  NOT substitute an in-memory advisory peak either.

* A **corroborated** peer is a discovered peer whose answer an independently drawn quorum agreed with,
  for ONE session (§18.6d). It has the same authority as an operator peer for that session only. The
  label MUST NOT be persisted and MUST NOT be cached against an address: what was verified is one answer
  at one height, not the peer's character.

The boundary is placed at the `initial_sync_complete` flag rather than at each individual leak because an
attacker chooses when its connection survives — closing the socket costs it one backoff cycle and buys a
fresh catch-up, which is how a per-leak defence is walked around.

18.6d. **Quorum-by-agreement: how a discovered peer earns authority.** dig-node is a Chia LIGHT CLIENT.
Almost no installation has an operator-chosen peer, so a rule under which only operator peers may write
means the shipped default never syncs at all: `initial_sync_complete` stays false and
`sync_state.peak_height` stays NULL indefinitely. There are no operator-chosen peers to fall back on, so
trust MUST instead be established by AGREEMENT among randomly selected discovered peers.

**The rule.** Before a discovered peer's session performs any write, the implementation MUST:

1. **Dial wide, then hold back.** Dial up to `QUORUM_DIAL_WIDE` = **10** peers by repeated independent
   discovery dials, keeping only DISTINCT peer addresses, then narrow that set to at most `QUORUM_HOLD` =
   **5** peers to ASK. Selection MUST NOT be biased by peer ordering, by first-responder-wins, or by a
   cached fastest-peer list, and any explicit index selection MUST use a cryptographically secure random
   source (the OS CSPRNG) with rejection sampling rather than modulo reduction.

   The narrowing MUST NOT rank by RESPONSIVENESS or by CLAIMED HEIGHT, because a fast always-up node is
   cheap to run and a claim is free, so ranking by either hands the choice to an attacker. Membership of
   the credibility band of step 2 is the criterion, and where more band members survive than are to be
   held, the choice among them MUST be random.

   Band membership is unsteerable by ONE peer and steerable by a COORDINATED HALF, and the implementation
   MUST NOT be written as though the first property were the whole of it. The band is anchored on the
   median claim, so peers holding half or more of the claims own the median and can place the band away
   from the honest set entirely while claiming nothing more implausible than being four blocks behind.
   Therefore: **a round in which the band excluded HALF OR MORE of the peers that supplied a peak claim
   MUST be refused, and MUST NOT proceed on the peers that survived the band.** The denominator is the
   peers that CLAIMED a peak — it MUST NOT be the dial target, and it MUST NOT be the number of peers
   that answered the settled-height question, because keying on either refuses a thin honest round and
   re-creates the frozen replica described below.

   Over-subscribing is a LIVENESS measure: dialling exactly as many peers as a round needs leaves it no
   margin for a dial that is stale, slow, or gone by the time the question is put.
2. Compare their claimed peaks and EXCLUDE any peer whose claim is further than `PEAK_LAG_TOLERANCE` =
   **3** blocks from the MEDIAN claim, in either direction. The median is REQUIRED: anchoring on the
   maximum lets a single peer claiming `u32::MAX` place every honest peer outside the band and be left
   alone in the pool. A median is immune to ONE outlier and not to a coordinated half; the refusal
   required in step 1 is what covers the remainder.
3. NORMALISE the question to a settled height `H = min(claimed peaks of the sample) − SETTLED_LAG`, with
   `SETTLED_LAG` = **2**. Every quorum question MUST be asked as of `H`, never as of the tip.
4. Ask every held peer, and the would-be writer, the same question at `H`. The writer MUST NOT choose
   `H`.
5. Elevate the writer to **corroborated** if and only if the round reached a verdict AND the writer's own
   answer equals it. A round reaches a verdict when at least `required_agreement(answered)` of the peers
   that ANSWERED returned the same answer.

**A round proceeds on the peers that ANSWERED; it MUST NOT wait for a fixed number of answers.** An
implementation MUST NOT discard a round because fewer peers replied than were asked. Requiring a fixed
answer count is not a security property — an attacker who can silence a peer can force the wait
indefinitely — and it is a liveness defect with a measured cost: a replica held at height 9,139,211 for
hours, five peers connected, the chain ~2,500 blocks ahead, because one peer of five was slow.

**Corroboration is a CONFIDENCE GRADIENT, not a gate.** Every verdict MUST carry `agreed`, the number of
independent peers that gave the answer, so the confidence travels WITH the datum. More agreeing peers
means a better-attested datum; it MUST NOT mean the difference between a datum and nothing.

**Two answers is the FLOOR, and this is an ASSUMPTION.** `CORROBORATION_FLOOR` = **2**. A single source is
never corroboration: one peer agreeing with itself is one peer, and accepting it would reinstate exactly
the single-untrusted-source problem this section exists to remove. This floor is recorded as an
assumption rather than a derived constant — it encodes a judgement about what the word "corroborated" is
allowed to mean, and the operator of a node may reasonably overturn it in either direction.

It MUST NOT be raised to 3 in the name of hardening. The round that froze a user's installed node
reported `Insufficient { answered: 2, required: 4 }` — **two** peers answered, not four — so a floor of 3
refuses that round for as long as the network stays that thin, which is the same freeze reached by
another route. A thin round's strength comes from the agreement ratio (two of two must agree) and from
the band refusal of step 1, never from demanding more answers than the network is offering.

**The AGREEMENT threshold MUST NOT be lowered to admit thinner rounds.** These are two different knobs and
only one of them was the defect. `required_agreement(answered)` = `max(CORROBORATION_FLOOR,
ceil(answered × QUORUM_AGREEMENT ÷ QUORUM_SAMPLE))` — the shipped three-quarters ratio, ROUNDED UP,
applied to whoever answered. `required_agreement(4)` is therefore exactly `QUORUM_AGREEMENT` = **3**, and
3-of-5 and 2-of-3 remain REFUSED. An implementation MUST NOT substitute a bare majority. Note the
direction: a wider round demands MORE agreement, so dialling wide never makes a verdict cheaper to
obtain.

**Behind versus lying.** Steps 2 and 3 exist because a peer that is merely BEHIND and a peer that is
LYING are indistinguishable in any single answer, and treating ordinary propagation lag as an attack is
itself a denial of service. At a settled height in the shared past, a lagging-but-honest peer and a fully
caught-up peer hold the SAME answer, so lag cannot produce disagreement. A peer that still disagrees, at a
height it claims to have passed, is lying, partitioned, or forked — never merely slow.

**Outcomes.** The implementation MUST behave as follows, and MUST NOT collapse these into one:

| Outcome | Meaning | Required behaviour |
|---|---|---|
| **Unanimous** — every peer that answered agrees | Corroborated | Elevate; the session may write. Carries `agreed`. |
| **Majority with dissent** — `required_agreement(answered)` agree, ≥1 does not | Corroborated, with evidence | Elevate, AND surface the dissenting peers. At a settled height a dissenter is not merely behind. Carries `agreed`. |
| **Split** — no answer reaches `required_agreement(answered)` | Truth UNKNOWN | Write NOTHING. Re-draw a FRESH random sample and retry. MUST NOT take the plurality. After `PERSISTENT_DISAGREEMENT_ROUNDS` = **3** consecutive splits, surface the standing disagreement as evidence of a partition or an attack. |
| **Insufficient** — fewer than `CORROBORATION_FLOOR` = 2 answered | Alone, not outvoted | Write NOTHING. A single answer MUST NOT corroborate itself. |

The retry obligation on a Split is discharged by ENDING the refused session: corroboration runs once per
session, so a refused session that is never ended is a refusal that never expires and no fresh sample is
ever drawn. An implementation MUST end a session that failed corroboration rather than holding it.

**A refusal MUST name WHICH party it accuses, and the three refusals are NOT interchangeable.** A round
that does not elevate its writer is one of exactly three things, and an implementation MUST distinguish
them:

| Refusal | The round | Required behaviour |
|---|---|---|
| **Undecided** — Split or Insufficient, or corroboration unavailable | The truth is unknown, so nothing is known about the writer | Write NOTHING. Count toward `PERSISTENT_DISAGREEMENT_ROUNDS`. Hold the session for `RECORROBORATE_AFTER`, then end it. |
| **Writer contradicted** — a verdict was reached and the writer answered something ELSE at `H` | The WRITER is the anomaly | Write NOTHING. Count toward `PERSISTENT_DISAGREEMENT_ROUNDS`. END THE SESSION AT ONCE so a different peer is dialled. |
| **Writer silent** — a verdict was reached and the writer did not answer at all | Nothing is evidenced | Write NOTHING. MUST NOT count toward `PERSISTENT_DISAGREEMENT_ROUNDS`. Hold for `RECORROBORATE_AFTER`, then end. |

The undecided round MUST be tested FIRST: without a verdict there is nothing for the writer to have
contradicted, and an implementation that compares answers first accuses an honest writer on every split.

**A contradicted writer is replaced; the quorum's answer is NOT adopted.** When four independently drawn
peers agree and the writer disagrees, the evidence points at the writer, so keeping it for a further
`RECORROBORATE_AFTER` preserves precisely the peer that failed while the replica goes unwritten. The
session MUST therefore end immediately. It MUST NOT become a write: the quorum's answer is settled at the
deliberately lagged `H`, so recording it would put a chain fact into `sync_state` with no write authority
holder — the bypass this whole section exists to prevent — and would in any case never track the tip.

**A probe that could not be answered is NOT evidence.** An implementation MUST NOT treat a
`header_hash_at` error, or an honest absence of an answer, as a contradiction. Silence is what a slow or
busy peer looks like, and counting it walks a node toward a partition warning it has no evidence for.

**The replacement MUST be bounded by the EXISTING reconnect ladder, with no new constant.** A refused
session is far shorter than `HEALTHY_SESSION`, so the backoff is not reset and doubles toward
`BACKOFF_MAX`. A permanent mismatch — including one caused locally rather than by any peer — therefore
converges on one dial per `BACKOFF_MAX`, never a dial loop.

**Reads that MUST be verified rather than voted on.** Voting on a locally decidable fact wastes round
trips and, worse, lets a majority overrule arithmetic. The following are SELF-VERIFYING and MUST be
checked locally, never put to a quorum:

* **A coin id.** It is `sha256(parent_coin_info ‖ puzzle_hash ‖ amount)`. An implementation MUST DERIVE
  the id from the coin's own fields and MUST NOT store a peer-supplied id.
* **A header block's hash.** `HeaderBlock::header_hash()` folds the block's own foliage, so "is this the
  block you named?" is decidable locally. WHICH header hash is canonical at a height is NOT decidable
  locally and IS the quorum'd question; the two MUST NOT be conflated.
* **The genesis challenge and network id.** These are pinned by the node and enforced by the peer
  handshake. No quorum may change them.

**Spentness is monotone and MUST NOT be voted on.** Believing a spent coin is spendable produces a double
spend; believing a spendable coin is spent produces a smaller balance and a retry. Resolution is
therefore fail-closed union, not majority rule: ANY credible report of SPENT marks the coin spent, even a
lone one, while UNSPENT requires the WHOLE sample to answer and to agree. A peer that did not answer
counts against unspentness. Only a coin the whole sample reported unspent at the settled height is
selectable on the spend path.

**The corroborated read is the one that reaches coin selection.** There MUST NOT be a separate display
path carrying an uncorroborated single-peer read. `routing::route` gates wallet-scoped reads on
`initial_sync_complete`, and that flag MUST be reachable only through an operator or corroborated
session.

18.6e. **The Sybil limit, stated honestly.** Random selection raises an attacker's cost; it does NOT
eliminate the attack, and an implementation MUST NOT imply otherwise to a user.

An attacker controlling a fraction `f` of the discoverable peer set carries a 3-of-4 round with
probability `P(≥3 hostile of 4)`: about **0.4%** at `f = 0.1`, about **8%** at `f = 0.3`, and about
**31%** at `f = 0.5`. As `f` approaches 1, agreement degrades to agreement among the attacker's own
peers and the model provides no protection whatever.

**A THIN round is easier to capture, and the published figure MUST say which round size it describes.**
Because a round now proceeds on the peers that answered, its size varies, and quoting a wide round's
comfortable number for every round would hide the difference. At `f = 0.3`: a round at
`CORROBORATION_FLOOR` = 2 is carried about **9%** of the time (both answerers hostile), a 4-answer round
about **8%**, a 5-answer round about **3%**. So an attacker who can make witnesses UNREACHABLE has a
cheaper path than out-voting them — that is the accepted price of not freezing, and `QUORUM_DIAL_WIDE`
over-subscribing to keep rounds wide is the mitigation, not a cure.

Three further limits are part of the honest statement:

* **Denial is cheaper than forgery.** Dissenting past `required_agreement(answered)` forces a Split and
  stalls the write, which needs fewer hostile peers than forging a verdict. This asymmetry is deliberate:
  a stalled sync is visible and recoverable, a forged one is neither.
* **A round can be made thin ON PURPOSE, and that is not the same risk as a round that is thin by
  accident.** The figures above model BENIGN shrinkage — peers that were slow or gone. An attacker who
  supplies half the claims does not have to wait for that: because the credibility band is anchored on
  the median claim, half the claimants announcing an ordinary lag place every honest peer outside the
  band, leaving a round composed entirely of the attacker's peers, unanimous by construction. Measured
  against the shipped selection, this took forgery from about **8.4% to 15.0%** at `f = 0.3` and from
  about **31.3% to 62.3%** at `f = 0.5`, with the crossover at `f ≈ 0.17` (that crossover compares the
  pre-change fixed-sample design against the post-change design with the step-1 refusal ABSENT).
  The refusal required in step 1 is what removes this path: it raises the attacker's bar to a strict
  majority of the claimants — 6 of a 10-peer dial, which is **60%** of the round, against the **75%**
  the 3-of-4 fixed-sample design required. The COUNT rose and the FRACTION fell, so an implementation
  MUST NOT state the counts alone or describe the refusal as uniformly stricter. Comparing
  `P(X ≥ 3)`, `X ~ Binom(4, f)` against `P(X ≥ 6)`, `X ~ Binom(10, f)`: **0.37% → 0.01%** at `f = 0.1`,
  **8.4% → 4.7%** at `f = 0.3`, **17.9% → 16.6%** at `f = 0.4`, and **31.3% → 37.7%** at `f = 0.5`.
  The refusal is therefore safer in the healthy regime and worse as the attacker approaches half the
  population, with its own crossover at **`f ≈ 0.42`** — a DIFFERENT number from the `f ≈ 0.17` above,
  and the two MUST NOT be conflated. Six of ten is the whole composite bar: a six-claimant attacker
  sets the median, survives the majority check, supplies the entire narrowed sample and meets
  `required_agreement` by construction, so no later stage adds a further hurdle.
* **Discovery selection is imperfectly random.** `connect_random_peer` tries `127.0.0.1` before any
  introducer and then returns the first address that connects, so a co-resident process and a fast,
  always-up node are both over-represented among probes. Requiring DISTINCT addresses within a round
  prevents one peer from supplying an entire quorum, but does not equalise the draw.
* **A corroborated session is not a corroborated peer.** Authority is granted per session and per answer.
  It MUST NOT be persisted.


Beyond the boundary, the supervisor MUST hold all four of the following for an operator peer too.

* **Subscription filtering.** A `CoinState` at a puzzle hash outside the set this session subscribed MUST
  be dropped, in both the catch-up response and every `coin_state_update` push. A peer answers a
  subscription; it does not define one.
* **A bounded fork depth.** A `coin_state_update` claiming a fork more than 128 blocks below the replica's
  peak MUST be refused and the session dropped, with the replica left intact. A light client cannot
  validate a fork claim, and `rollback_above(0)` erases the whole replica.
* **A bounded rollback SEQUENCE.** An applied rollback lowers the peak, so the next frame's 128 blocks
  are measured from the new mark and a peer that never exceeds the per-frame bound still walks the
  replica down indefinitely. One session MUST therefore be dropped once its rollbacks total more than 128
  blocks, however many individually-legal frames they arrived in.
* **Fail closed on any backwards move.** When a rollback is applied, or the update's height is below the
  current peak, `initial_sync_complete` MUST be cleared. Wallet-scoped reads then route to the fallback
  tier (§18.7) until a later sync pass re-establishes the flag — an address-history catch-up, or the
  oracle-tier point-read refresh, which is the other writer of it. Without this a single frame makes a funded
  wallet report `balance 0` with `phase: synced`.
* **A monotonic replica peak.** `new_peak_wallet` MUST only ADVANCE `sync_state.peak_height`; a backwards
  claim is refused. That height bounds a claimed confirmation on an OPEN read, so a peer able to lower it
  can make settled money read unconfirmed.
* **A bounded replica peak.** A CORROBORATED writer MUST NOT raise `sync_state.peak_height` above an
  absolute per-session ceiling, anchored on the height its corroboration round settled (a height that
  writer cannot inflate, because elevation requires it to AGREE with that height). The allowance above the
  anchor is `128 + session_lifetime / 9s` blocks — the same 128 the rollback bound uses, making the bound
  symmetric, plus chain progress budgeted at about half the target block time so a burst still fits. The
  ceiling is FIXED for the session and MUST NOT ratchet; session rotation refreshes it by re-corroborating.
  An OPERATOR session has NO ceiling: the operator chose that address by hand and no independent anchor
  exists on that path. ALL THREE peak-carrying writes are bound by it — a `new_peak_wallet`
  frame, a `coin_state_update` frame, and the terminal height of a catch-up. An over-ceiling
  `new_peak_wallet` or `coin_state_update` MUST drop the whole FRAME before it acts (leaving the replica
  peak still, so the sync phase and the stall detector both keep seeing the real gap, and leaving any
  rollback the frame asked for undone, because a frame whose height is a lie is suspect in its entirety);
  the third such frame in one session MUST end the session so a fresh quorum is drawn. An over-ceiling catch-up TERMINAL MUST
  end the session immediately and MUST NOT arm `initial_sync_complete` or the arrival baseline. Without
  this bound one accepted frame makes unconfirmed money read as confirmed for the life of the process, and
  permanently disables both the sync-phase gap check and the stall detector, which saturate into agreement
  with an inflated peak.

18.6b. **The observable sync status.** `control.wallet.syncStatus` reports `{phase, peak_height,
chia_peer_count, subscription_peer_count, chia_peer_peak_height, watched_addresses}`. `phase` is `not_started` (no peer has ever attached), `syncing`,
`synced`, `no_wallet_enrolled` or `wallet_not_unlocked` — and `synced` requires a completed catch-up, a live
SUBSCRIPTION peer (`subscription_peer_count >= 1`, NOT `chia_peer_count`), AND the replica actually
FOLLOWING the chain, so a replica that caught up and then went
offline reports `syncing`. The phase describes the REPLICA, so it keys off the session that writes the replica; held
read-serving peers do not make a stale replica current.

**`synced` MUST be a claim about NOW.** A completed catch-up is a latched fact about the past and a peer
count says only that a socket exists, so a node MUST additionally require that `peak_height` trails
`chia_peer_peak_height` by AT MOST 4 blocks (about 75 seconds of chain); beyond that it reports `syncing`.
A `null` on EITHER height is unobservable and MUST NOT be read as evidence of a gap — the phase is then
exactly what it would have been without this rule. The tolerance is deliberately strict, because the two
failure directions are not symmetric: reporting `syncing` on a healthy node understates confidence
harmlessly, whereas reporting `synced` over a frozen replica tells a client that a stale balance is
settled. It is deliberately NOT the same threshold as the 90-second stall deadline of §18.6a: that one
decides whether to pay for a catch-up from genesis, this one decides what may be claimed about a number
already being served.

`peak_height` is the REPLICA's own height read
from `sync_state`; it MUST NOT fall back to the coinset oracle (unlike `control.wallet.peak`, which answers
a different question), and `null` means unknown, never height zero.

**The node reports TWO Chia peer counts, and they are different sets.** `chia_peer_count` is the Chia full
nodes the node HOLDS — the chain transport's pool, which serves its chain reads. It MUST be the LIVE size
of that pool and MUST NOT be the configured target: a pool still filling reports the smaller number.
`subscription_peer_count` is the replica's subscription session, at most ONE by design. Each is `0` when
observed and `null` when unobservable, and a consumer MUST NOT add them. A node MUST NOT report the
subscription session as `chia_peer_count`: doing so made a node holding five peers and serving every read
from them announce `chia_peer_count: 1`, a figure that was neither the peers serving reads nor the total.

**`chia_peer_count` MUST be a MEASUREMENT, and `null` when it cannot be one.** The pool it counts
evicts an entry only when a request to that peer FAILS, and the node reads the chain through a tier that
consults the coinset HTTP API first — so a node whose reads are all answered by coinset never routes a
request to a peer, never ejects one, and never has its held-peer belief contradicted. That belief then has
unbounded age. A node MUST therefore report the count only while its held peers have shown a sign of life
within a bounded window, and MUST report `null` otherwise. The two admissible signs of life are the peers'
announced peak ADVANCING and the held count itself CHANGING; both are facts about this node's sockets, and a
peer claim about itself is NOT one (NC-12). Unknown MUST NOT be reported as `0`. The window is satisfied
by AT LEAST ONE held peer showing a sign of life, not by all of them: the pool's peak is a `fetch_max`
across per-peer tasks, so a single live socket refreshes the stamp for the whole count. A reported count
therefore asserts that the set is not wholly dead — never that every counted peer is individually live.

**A node MUST NOT offer a peer a decisive quorum has just caught contradicting it as that peer's own
replacement.** When a corroboration round refuses a writer with `WriterContradicted`, the dial that
replaces it MUST exclude that address. Refusals that name no culprit — a split, a silent writer — MUST NOT
exclude anyone: an exclusion applied on every refusal narrows the set a random dial can reach, which is the
plurality corroboration depends on. The exclusion is a hint and MUST fail OPEN: an implementation that
cannot honour it MUST still connect.

**A node with chain sync enabled MUST hold its Chia peers because it is running**, not because a read
happened to build them. The chain transport is connected in the background at start-up and RETRIED, so a
node that booted before its network came up does not stay peerless for the life of the process. Asking for
the peer tier MUST NOT itself dial: a status call cannot be the act that makes the node hold peers.

`chia_peer_peak_height` is the peak those held peers ANNOUNCED to this node. It is distinct from
`peak_height` (the replica's own progress) and from any oracle reading, and it MUST NOT be sourced from
one: a peak fetched from a public HTTP oracle evidences nothing about the node's peers. `null` means no
peer has announced one yet, never height zero.

**`chia_peer_peak_height` is UNVALIDATED EVIDENCE, and both readers of it MUST treat it as such.** It is
a monotone MAXIMUM over unverified `NewPeakWallet` claims: no quorum settles it, no peer is corroborated
before contributing to it, and it never falls, so ANY single peer in the pool pins it arbitrarily high
with one frame. Anchoring on a maximum is exactly what §18.6d's peer selection REFUSES to do — a single
peer claiming `u32::MAX` would otherwise become the reference point and put every honest peer outside
the credibility band — and this figure is deliberately NOT the anchor for the §18.6a peak ceiling, which
is anchored on a corroborated settled height precisely because that one cannot be inflated by the peer
it bounds. The settled height's own bound is narrower than "cannot be inflated", and MUST be read as
what it is: it is the MINIMUM of the credible claims, so it cannot lead the true tip while any credible
claim is honest, and a coordinated MAJORITY of the peers that claimed a peak owns the credibility band
and can place it arbitrarily high. A single peer cannot, which is what this anchor asserts.

It is used only where an inflated value costs a NEEDLESS RECONNECT and never a money claim. An
over-stated peers' peak can make a healthy replica report `syncing` instead of `synced`, and can end an
otherwise healthy session as stalled so a fresh peer is dialled; both understate confidence and cost
work, and neither writes the replica, raises a peak, or makes unconfirmed money read as confirmed. A
node MUST NOT extend this figure to any use where being wrong in the inflating direction would be
believed — in particular it MUST NOT bound a claimed confirmation, for which `peak_height` is the only
admissible height.

`control.peerCounts` reports `{dig_peer_count, chia_peer_count,
known_dig_peer_count}`, and its `chia_peer_count` MUST be the SAME observation this method reports.

**The two nothing-to-watch phases are DEFAULT-INSTALL states and MUST NOT be reported as `syncing`.** A
node that has NEVER enrolled a wallet holds zero puzzle hashes; §18.6 REFUSES a catch-up over an empty set,
so on that node `initial_sync_complete` never latches, while `new_peak_wallet` keeps the replica's peak
advancing with the chain indefinitely. Three facts establish that a session is watching nothing: a Chia peer
is attached RIGHT NOW; that peer's effective trust is authoritative (`Operator` or `Corroborated`, §18.6a)
so it MAY write; and the attached session resolved a MEASURED-EMPTY address set. The trust condition is
load-bearing — an uncorroborated writer's subscription set is forced empty too, and that replica is
deliberately NOT being written and IS falling behind, so reporting it as nothing-to-watch would present a
stalled replica as a healthy one.

**The nothing-to-watch determination OUTRANKS `synced`, and that ORDER IS NORMATIVE.** A wallet that
enrolled, completed a catch-up, and was then RESTARTED carries a latched `initial_sync_complete` — the flag
is persistent, and only a backwards chain move clears it — while its addresses are not derivable because it
is locked. A node MUST NOT report `synced` in that state; it MUST report `wallet_not_unlocked`. The latched
flag records that a catch-up once finished, which is true and irrelevant to whether THIS session is
following the user's coins. Testing `synced` first is exactly the defect dig_ecosystem#2609 removed: it
reported `synced` beside `watched_addresses: 0` — settled, while the user's coins were not being followed —
on the most common post-restart path there is.

**A REFUSED writer is a KNOWN GAP, stated rather than glossed (dig_ecosystem#2666).** Because the empty-set
determination requires an authoritative peer, an uncorroborated writer skips it and a node whose
`initial_sync_complete` is latched reports `synced` while watching nothing and while its replica peak is
frozen — §18.6a drops every `new_peak_wallet` from a non-authoritative peer. That is a stale reading
presented as a current one, and it is NOT yet fixed. A conforming implementation SHOULD additionally
require an authoritative peer before reporting `synced`; this specification will make that a MUST once
#2666 lands.

A FOURTH fact decides WHICH of the two, and they mean opposite things. The node MUST read it from custody's
MANIFEST (is any wallet enrolled) and MUST NOT infer it from the derivable key set, which is empty for a
locked wallet:

- **`no_wallet_enrolled`** — no wallet exists, so watching nothing is correct and complete. A consumer MAY
  present this as settled. `watched_addresses` is `0`.
- **`wallet_not_unlocked`** — a wallet EXISTS and its addresses are not being followed, so the user's coins
  are not being watched and their balance is not being maintained. This is the COMMON state after every
  restart: the address set derives from key material the node cannot reach while the wallet is locked, and
  nothing back-fills it; an adopted legacy seed, a manifest predating the stored-public-keys field, a
  self-healed manifest, and an entry whose key fails to decode all reach it too. A consumer MUST NOT render
  it as synced, settled, or up to date, and MUST NOT present a balance read under it as complete. It is
  named NOT UNLOCKED rather than *locked* because an empty address set is what the node can OBSERVE and a
  lock is only its usual cause.

Neither MUST be folded into `synced`, which additionally licenses §18.7 routing wallet-scoped reads to the
local replica; latching that over an un-queried DB reads a funded wallet as empty.

`watched_addresses` reports how many addresses the attached session resolved: a MEASURED `0`, a positive
count, or `null` when no attached session has resolved a set yet — a peer mid-corroboration, or none
attached. A consumer MUST NOT read `null` as `0`.

**The phase token set is normative and lives in `dig-node-control-interface`.** The tokens are exactly
`WalletSyncPhase::ALL`: `not_started`, `syncing`, `synced`, `no_wallet_enrolled`, `wallet_not_unlocked`. A
node MUST NOT emit a token outside that list, and a new phase MUST be published in that crate BEFORE a node
emits it — an undeclared token fails a consumer's ENTIRE `WalletSyncStatusResult` parse rather than
degrading one field, so the surface renders nothing at all. Consumers MUST treat an unrecognised token as
UNKNOWN and MUST NOT infer progress, completion, or a trustworthy balance from it.

18.6c. **The known DIG peer count.** `control.peerCounts.known_dig_peer_count` is the number of DIG peers
this node has LEARNED OF, connected or not — the size of the gossip layer's discovered-peer address book,
which the node also surfaces as `control.peerStatus.known_peers`. The node MUST source it from that
address book and MUST NOT derive it from `connected_peers`: the field exists precisely to distinguish a
REACHABILITY fault (no connections despite a populated address book) from a DISCOVERY fault (an empty
one), and an aliased count reports both as the same zero. `null` means the node has not sampled the
address book — a not-running peer network, or a pool loop that has not yet run its first pass — and MUST
NOT be reported as `0`, which would claim an emptiness never observed.

The count is this NODE's local view and a LOWER BOUND. Neither the node nor any client may present it as
the size of the DIG network or as a total peer count: it omits every peer this node has not been
introduced to, every peer reachable only via a relay it does not use, and every address-book entry evicted
under the gossip layer's bucket limits. It is also distinct from `control.peerStatus`'s `relay.peer_count`,
which is the RELAY's view of its own registrations.

18.7. **Fallback tier + sync-state-gated routing.** `chia-query` (coinset.org + non-subscribing peer
point-reads) is reused AS-IS as a fallback tier — never the primary. The B.3 subscription loop is NOT
added to `chia-query`. Every wallet-data read selects its source:

| Condition                                            | Source           |
|------------------------------------------------------|------------------|
| Wallet's own data, DB synced to peak                 | Local wallet DB  |
| Wallet's own data, DB still syncing                  | Fallback tier    |
| Chain data not scoped to this wallet, not in the DB  | Fallback tier    |

So a caller never blocks on an unsynced replica. `get_sync_status` reports the gating sync state.

**Spend inputs take the same gate — EVERY reader, not the XCH ones.** Selecting the coins a spend is
built from is a wallet-scoped read of the same replica, so EVERY reader whose rows become spend inputs
MUST consult this table on its OWN account: the XCH selector, the caller-named-coin reader, the CAT
selector, and the singleton (NFT/DID/option) input reader. A reader that reaches the gate only through a
SIBLING read does not satisfy this — the CAT selector once did so only via the XCH coins it picked to pay
a fee, and only when that fee was non-zero, leaving the ordinary fee-0 path ungated. The gate MUST be
consulted before any other precondition of the reader, so an unauthoritative replica is refused for being
unauthoritative. Concretely, it MUST consult this table: with the replica unsynced, the node MUST REFUSE to build
the spend rather than select inputs from a table it is not entitled to assert yet. A per-coin fallback is
not a substitute — the fallback tier can confirm that a coin exists, but the SET of spendable coins is
exactly what an unsynced replica cannot claim. The remedy available to a caller is to complete an
authoritative sync (an operator peer, or the point-read refresh of §18.12).

18.7aa. **ARBITRARY coin reads are served by the node's OWN peers, corroborated (dig_ecosystem#3032).**
`control.wallet.coinById` and `control.wallet.coinSpend` name coins that are not the wallet's own, so the
replica structurally cannot answer them — a lineage walk, which is how a dig-profile is resolved, touches
coins at nobody's watched address. Those two reads MUST be served, after the replica miss of §18.7, by
asking the node's OWN dialled Chia full nodes; they MUST NOT be routed to a configured upstream endpoint.
A single endpoint answering arbitrary chain reads is a trusted peer under another name, and a node that
has none configured could otherwise not read its owner's profile at all while holding five peers that
could have answered.

Every such peer is UNTRUSTED (NC-12) and the node MUST NOT grant one a trusted/local-node classification.
An answer is authoritative ONLY when it is given by at least `CORROBORATION_FLOOR` independently drawn
peers and reaches the same agreement threshold every other quorum'd read uses; the peers asked MUST be
distinct addresses, MUST be independently discovered (a preferred or co-resident address is a good peer to
ask and not an independent voice), and MUST be periodically redrawn rather than held for the life of the
process. A round that cannot assemble agreement is UNKNOWN — a DISTINCT error, NEVER `null` — because a
caller walking a lineage reads absence as *this is the tip* and stops. Each peer's answer MUST be bound to
the question locally BEFORE it is counted: the coin id is recomputed from the coin the peer sent, and a
spend's `puzzle_reveal` MUST tree-hash to the spent coin's `puzzle_hash`. Both checks are per-peer, not
post-tally, so a peer sending an unverifiable program is excluded from the round rather than carried into
a majority by honest peers.

Corroborated answers MUST be cached in the wallet database, keyed on the coin id. Because a coin id is
`SHA256(parent ‖ puzzle_hash ‖ amount)`, an entry cannot be wrong for its key; it can only go stale in
`spent_height`. So a SPENT coin record and a SPEND are cached indefinitely (a spend cannot un-happen),
while an UNSPENT record MUST expire, since caching "unspent" forever would make a profile look permanently
stale. A corroborated ABSENCE MUST NOT be cached: a coin that does not exist yet may exist in a minute.

Each cache MUST be BOUNDED and MUST evict by recency of USE (dig_ecosystem#3035). `control.wallet.coinById`
is an OPEN read, so every distinct coin id an unauthenticated caller asks for writes a row, and the rate
bound limits the RATE, never the TOTAL; a cache that is mostly permanent by design is therefore a
disk-exhaustion path unless its SIZE is bounded. The node MUST NOT bound it by shortening the permanent
entries' lifetime instead: a lineage walk touches a SPENT coin at every generation but the last, and that
permanence is what makes the walk affordable. Eviction MUST rank by when an entry was last USED rather than
when it was written, because the entries worth keeping are the ones a walk re-reads. The shipped budgets are
50 000 coin records and 10 000 spends — together roughly 60 MiB, deliberately small beside the capsule cache
(1 GiB) and the content cache (256 MiB), since every evicted answer can be re-asked in one round.

A CACHED row MUST be re-verified on the way OUT, not only on the way in. A served spend's `puzzle_reveal`
MUST tree-hash to its `puzzle_hash`, and for both caches the row's own `parent_coin_info`, `puzzle_hash` and
`amount` MUST hash to the coin id the row is stored under. Comparing a row's `coin_id` COLUMN to the lookup
key does NOT satisfy this — that column is the key the row was selected by, so the comparison cannot fail.
The rows never expire, so a check applied only at write time is a check that a second writer of either
table, present or future, silently bypasses.

18.7a. **Identity-scoped reads + honest sync state (#407).** The dig-node answers wallet-data reads for
the CLIENT's connected self-custody wallet, scoped by that wallet's PUBLIC identity — NEVER the node's
own coins, and NEVER holding the client's private key (the node receives only public puzzle
hashes/addresses).

- **Session identity via `login`.** `login` accepts, in addition to `fingerprint`, an OPTIONAL
  `puzzle_hashes` (hex) and/or `addresses` (bech32m, decoded to puzzle hashes). When either is present
  the node records a per-session identity (the set of PUBLIC puzzle hashes) and scopes subsequent reads
  to it; `logout` clears it. These fields are additive — a Sage client sending only `fingerprint`
  deserializes unchanged and seeds no identity. The node MUST subscribe the declared puzzle hashes for
  chain-watch so the local DB converges to the client's coins.
- **Read scoping.** `get_sync_status` (XCH balance), `get_cats`/`get_token`/`get_all_cats` (CAT
  balances), and `get_coins`/`get_spendable_coin_count` filter to the session identity's coins: XCH
  coins by `puzzle_hash ∈ identity`, CAT coins by `hint ∈ identity` (a CAT sits at the outer CAT puzzle
  hash and is hinted to the owner p2). Absent a session identity, reads fall back to the node's own
  configured puzzle hashes (legacy); when BOTH are empty the node is tracking no wallet and scoped reads
  return nothing.
- **A balance is never reported for a scope the replica does not cover.** Every balance-bearing read
  — `get_sync_status`, `get_token`, `get_cats`, `get_all_cats`, `get_coins` — MUST first establish that
  the completed catch-up COVERS the session identity's addresses. The replica is only ever asked to
  follow the addresses a catch-up ran over, so querying it for an uncovered identity returns nothing,
  and nothing is reported downstream as a chain-confirmed zero. Note that `login` does NOT enrol: a
  client that logs in without `control.wallet.watch` is never covered, so this state is permanent
  rather than transient and cannot be waited out.

  An uncovered scope MUST be answered by one of exactly two shapes, and never by a zero. Where the
  chain can be asked directly — XCH coins, which sit AT the identity's puzzle hashes — the read is
  ROUTED to the chain source, and its confirmed-and-unspent predicate MUST be re-applied to that
  answer, since a chain read returns recently-spent coins too. Where the chain cannot answer — a CAT,
  which is only HINTED to its owner and needs puzzle uncurrying the fallback tier does not perform, and
  the CAT LIST, which is itself a replica read — the node MUST REFUSE with `unavailable`. The gate on
  the list is required independently of the gate on each token: an uncovered scope yields no asset ids,
  so a per-token gate is never reached and the caller is told it owns no CATs.

  The predicate MUST be containment of the CLIENT's scope, never whether the replica is authoritative
  over its own followed set: under the node-holds-no-custody rule that followed set may be empty, every
  recording trivially contains it, and the gate would pass for every client while changing nothing.

- **Honest sync state (never a silent synced-zero).** `get_sync_status` reports `synced_coins`/
  `total_coins` TRUTHFULLY. A client derives "synced" as `synced_coins >= total_coins` (treating
  `total_coins == 0` as synced). The node reports synced ONLY when it is tracking the identity AND the
  DB has completed initial catch-up (`is_synced()`); otherwise it reports `synced_coins < total_coins`
  (`0` of at-least-`1`), so an empty or not-yet-caught-up DB, and a wallet the node is not tracking,
  read as NOT synced and never as a synced-zero. `selectable_balance` is the identity-scoped unspent XCH
  balance (0 when not tracking).

18.7b. **Tier disclosure — the reported state describes the ANSWER, not the node (#2233).** Every
wallet read that chooses a source per the §18.7 routing table MUST disclose the tier that actually
answered, and MUST derive every freshness field from that tier.

- **`source` is additive and REQUIRED on the result.** `control.wallet.balance` returns
  `source: "db" | "fallback"` alongside its figures. `"db"` means the node's own chain replica
  produced the figure; `"fallback"` means a third-party coinset HTTP oracle did, which additionally
  means the queried address WAS DISCLOSED off-node — a fact a caller on a metered or private
  connection has a legitimate interest in. The field is additive per §5.1: a consumer that does not
  read it parses unchanged.
- **`synced` and `peak_height` are properties of the tier, and `synced` is MEASURED.** A `"db"`
  answer reports the replica's own peak, and reports `synced: true` **only if the replica is
  FOLLOWING the chain right now** — the same `is_following` test `control.wallet.syncStatus` derives
  its phase from, so the two endpoints MUST NOT disagree about the same moment. An implementation
  MUST NOT report `synced: true` merely because the replica was eligible to answer: the flag that
  selects the tier, `initial_sync_complete`, LATCHES — it records that a catch-up once finished and
  is cleared only by a backwards chain move — so a replica hundreds of blocks behind still routes to
  `"db"`, and reporting its figure as current tells a client a stale balance is settled.

  A `"db"` answer with `synced: false` alongside a `peak_height` is a REAL figure, as of that height,
  and MUST still be served. It does not mean the figure is unknown, and an implementation MUST NOT
  withhold it or blank the peak: `peak_height` is what makes a stale answer usable rather than
  merely suspect.

  **A money read narrows `is_following` in exactly ONE direction: an UNOBSERVABLE peer tier — no
  chain peer has announced a height — MUST answer `synced: false`.** `is_following` itself answers
  `true` there, and MUST continue to, because on `control.wallet.syncStatus` an absent second
  opinion is not an accusation against the replica. On a money read it is the opposite: with no peer
  height to compare against, nothing has established that the figure is current, so `synced: true`
  would rest on the latched `initial_sync_complete` this rule exists to stop trusting — the state a
  freshly started node, or one with no reachable chain peer, sits in. The figure is still SERVED
  with its real `peak_height`, per the paragraph above. Wherever a peer height DOES exist the two
  endpoints apply the identical test, so they still cannot disagree about the same moment.

  A `"fallback"` answer reports `synced: false` and `peak_height: null`, **regardless of the local
  DB's state** — the DB neither produced that figure nor bounds its freshness, so its flag and peak
  say nothing about it. Implementations MUST NOT read those two fields outside the tier decision.
- **Rationale — this is the falsifiability instrument for §18.6.** A success criterion phrased as a
  flag value rather than as the path taken is satisfiable with the goal unmet: once the §18.6 sync
  loop sets `initial_sync_complete`, a read still served by the oracle would report itself as a
  synced local read. Acceptance for any sync work MUST name the `source` tier, never the `synced`
  flag alone.
- **Operator visibility.** The routing branch emits a `tracing` event carrying `tier=db|fallback`,
  so `dig-node.jsonl` records the same tier the wire reports. Diagnostics go through `tracing`,
  never stderr (a Windows service discards it).

  **The FALLBACK tier MUST be logged at a level a stock node actually emits.** `dig-logging`'s
  baked-in default is `info` and a default install sets none of the overrides, so a `debug!` here is
  invisible in the field — which would make the sentence above false on every stock node, and would
  let an acceptance run reading `dig-node.jsonl` mistake silence for "no fallback occurred". Fallback
  is therefore `info`; it is the exceptional path and it means the read was disclosed to a
  third-party oracle. The DB tier stays `debug`: once the §18.6 sync loop lands it is the ordinary
  path, and logging every local read at `info` would turn an OPEN unauthenticated loopback endpoint
  into a log-volume lever.

18.7a. **Derivation coverage — both trees, and the window follows use.** A custodied wallet MUST
cover BOTH the unhardened and the hardened HD tree. Chia farmer and pool rewards are paid to
HARDENED derivations, so a wallet covering only the unhardened tree cannot see them at ANY index.

The covered window MUST have a floor of at least 500 indices per tree, and MUST NOT be a constant: a
wallet observed using an index within a gap limit of the window's edge MUST extend past it, so the
addresses it is about to be paid at are both watched and spendable. Extension MUST be bounded, so a
corrupt or hostile persisted count cannot turn an unlock into unbounded key derivation.

The signer and the watched set MUST widen TOGETHER. Widening only the watched set converts "the user
cannot see their coin" into "the user can see their coin and cannot spend it", which is worse — it
reads as a send bug rather than a coverage bug.

Evidence of use is the p2 puzzle hashes the local replica has seen ANY coin at, SPENT coins included:
a coin that arrived at an index and was later spent is still proof that index was handed out. The
scan can therefore only follow a wallet outgrowing its window from INSIDE; history that begins beyond
the window is not discoverable this way, and is covered by the floor.

A wallet whose coins lie outside the covered window MUST NOT be reported as `synced` over a balance
that omits them — a confidently wrong, lower balance is the failure this clause exists to prevent.

18.9a. **In-flight coin reservation.** A spend bundle this node pushes and that the mempool ACCEPTS
MUST have its input coins reserved: recorded as committed and withheld from subsequent spend-input
selection. Without it, two sends inside the confirmation window select the same coin — the replica
only learns a coin is spent when a peer reports it, tens of seconds later — and the second is a
guaranteed mempool refusal the caller cannot act on.

A REFUSED push MUST reserve nothing; those coins were never committed.

Coin identity across the reservation store MUST be compared case-INSENSITIVELY. A coin id is hex, so
the same coin can be recorded in either case by different sources; a raw comparison makes an
upper-case coin fail to match its own reservation, which neither withholds it from selection nor lets
its bundle retire on settlement — the coin stays frozen for the whole expiry over a spend the chain
already completed.

Reservation MUST affect spend-input selection ONLY. Balance and display reads MUST keep counting a
reserved coin, because the chain has not said it is spent. "What do I own" and "what may I spend
next" are different questions.

**Hex storage.** Every hex value the replica stores and later compares — a coin's `coin_id` and
`parent_coin_info`, the three values a wallet read is SCOPED by (`puzzle_hash`, `asset_id`, `hint`),
and the hex columns keyed on outside the coin table (a derivation's `puzzle_hash`, a CAT's
`asset_id`) — MUST be normalised to LOWER-CASE hex at the point of WRITE, and every lookup that binds
a caller-supplied value against one of them MUST normalise it the same way. The chain source and the
calling client are each free to hand over either case, so a replica that stores it verbatim makes case
a hidden axis of every equality test: the node MUST NOT compare two stored hex values, or a stored
value against a supplied one, in a way whose answer depends on the case its source chose.

The consequence is not cosmetic and is stated as a requirement in its own right: **a coin the wallet
holds MUST count toward the reported balance regardless of the case its puzzle hash, asset id or hint
was spelled in.** A scoped read that misses such a coin reports the user a balance of zero, which is
indistinguishable from holding nothing.

Normalisation MUST be performed at the WRITER rather than by wrapping the stored column in a
case-folding function at each reader. Those columns are indexed or are primary keys, and a function
applied to a column makes its index unusable, so a reader-side fix degrades every scoped balance read
to a full table scan while repairing only the readers that remembered.

A replica written by an earlier build MUST be normalised in place before it is read, in ONE
transaction, and every table that keys or scopes a row by one of these values MUST be normalised in
that same transaction, since those values are compared against each other raw. Where several stored
spellings of one value would collide under that normalisation, the node MUST reduce them to one
deterministically rather than fail the migration — a migration that aborts is retried identically on
the next open and leaves the wallet permanently unopenable. Where the colliding rows carry state that
is NOT derivable from chain, that state MUST be merged onto the surviving row rather than dropped.

Every reservation MUST expire. Release is normally observational — the coin is seen spent, or the
bundle is definitively refused — and the expiry is the backstop that keeps a release path which never
runs from stranding a coin permanently. Failing to record a reservation MUST NOT fail a push that the
mempool already accepted.

A push MUST reserve its inputs unless the network DEFINITIVELY refused the bundle. A refusal is
definitive only when the mempool stated its reason (`accepted:false` WITH a `rejection`) AND that
reason is a property of the BUNDLE rather than of the answering node's own view; a bare denial
carrying no reason, a refusal whose stated reason is view-dependent, a refusal whose reason the node
does not recognise, and any transport failure MUST all be treated as POSSIBLY IN FLIGHT and hold the
inputs to the TTL.

A single push is not a single transmission: the chain client relays to UP TO THREE destinations in
turn and only the LAST answer is observed, and the earlier attempts fail in ways that do not
distinguish "never transmitted" from "transmitted, admitted, and the acknowledgement was lost". A
refusal MUST therefore NOT be read as the network's verdict merely because a destination stated one.
A reason that reports the answering node's OWN mempool or chain view — a conflict with a bundle it
already holds, a coin it has not yet seen, a relay-fee policy, a timelock evaluated against its own
peak — MUST NOT free the inputs, because the destination that answered may be refusing precisely
BECAUSE an earlier destination admitted the bundle.

The node cannot distinguish "never relayed" from "relayed, and the acknowledgement was lost", and
under §13 every dialled peer is untrusted, so a source that denies a relay it performed MUST NOT
thereby return the coins to selection — a second send inside the confirmation window could otherwise
reselect the same inputs. The TTL MUST NOT be shortened to compensate for the wider hold: that trades
a double-select for a lockout, and a lockout is the worse failure.

The set of bundle-intrinsic reasons MUST be an ALLOWLIST whose default is to HOLD. The reason text is
supplied by an untrusted source (§13), so an unrecognised reason MUST hold rather than free: the
enumeration cannot be complete, and a node MUST NOT be made to free a user's inputs by a reason
nobody foresaw. A node MUST match an allowlisted reason EXACTLY — never as a substring, prefix or
suffix — after trimming, and case-insensitively.

The allowlist is exactly these eleven Chia error names, and an independent implementation MUST use
this set: `BAD_AGGREGATE_SIGNATURE`, `COIN_AMOUNT_NEGATIVE`, `COIN_AMOUNT_EXCEEDS_MAXIMUM`,
`DUPLICATE_OUTPUT`, `MINTING_COIN`, `RESERVE_FEE_CONDITION_FAILED`, `WRONG_PUZZLE_HASH`,
`ASSERT_MY_COIN_ID_FAILED`, `ASSERT_MY_PARENT_ID_FAILED`, `ASSERT_MY_PUZZLEHASH_FAILED`,
`ASSERT_MY_AMOUNT_FAILED`.

A name MUST NOT be admitted to that set unless every node refuses it identically REGARDLESS of the
node's peak height, activated consensus flags, cost budget and mempool contents. The CLVM-execution
names — `GENERATOR_RUNTIME_ERROR`, `BLOCK_COST_EXCEEDS_MAX`, `INVALID_BLOCK_COST` and
`INVALID_SPEND_BUNDLE` — MUST NOT be admitted, even though they appear to be properties of the bytes:
bundle validation runs under flags derived from the answering node's height and under a
caller-supplied cost budget, so two honest nodes can disagree on identical bytes. `ASSERT_MY_BIRTH_*`
is view-dependent and MUST NOT be admitted either.

Requiring a STATED and BUNDLE-INTRINSIC reason is what keeps a mempool rejection the whole network
agrees on — a bad signature, say — from holding a user's coins for the full TTL. It does NOT keep a
view-dependent refusal from doing so, and MUST NOT be described as though it did: a bundle every node
will refuse for a reason outside the allowlist is held for the TTL, and that is the intended and safe
outcome.

18.8. **Method surface — reads (served).** `login`, `logout`, `get_version`,
`get_sync_status`, `check_address`, `get_derivations`, `get_are_coins_spendable`,
`get_spendable_coin_count`, `get_coins`, `get_coins_by_ids`, `get_cats`, `get_all_cats`, `get_token`,
`get_dids`, `get_nfts`, `get_nft`, `get_nft_data`, `get_nft_collections`, `get_nft_collection`,
`get_transactions`, `get_transaction`, `get_pending_transactions`, `is_asset_owned`, `get_key`,
`get_keys`. Coins and CAT balances/records are fully synced and served; transactions are derived from the
coin table grouped by created/spent height; NFT/DID/collection reads return the rows the sync
reconstruction populates (§18.11). `get_pending_transactions` MUST report the bundles this node has
pushed and not yet observed settling, read from the in-flight reservation store (§18.9a). A database
failure MUST be an error, never an empty list — an empty list is the positive claim that nothing is in
flight. Each record's `fee` MAY be `null` when the node could not compute it; a fee it does not know
MUST NOT be reported as `0`. That obligation binds every CONSUMER of the record as well as the node:
a client rendering a `null` fee as `0` re-creates the falsehood at the surface a person actually reads,
and MUST show it as unknown instead.

18.9. **Method surface — send/spend group (served, #216).** `send_xch`, `bulk_send_xch`, `send_cat`,
`bulk_send_cat`, `combine`, `split`, `multi_send`, `sign_coin_spends`, `view_coin_spends`,
`submit_transaction`. Spends are built with the canonical `chia-wallet-sdk` driver constructors
(`StandardLayer`/`SpendContext`/`Cat::spend_all`) — never hand-rolled CLVM — over coins selected from the
wallet DB; the built bundle is validated by `dig-clvm` (`validate_spend_bundle`) BEFORE any broadcast
(fail-closed). Because `dig-clvm` is the DIG **L2** consensus engine, its aggregate-signature check uses
the DIG-L2 domain (not the Chia **L1** domain a wallet spend is signed for), so pre-broadcast validation
runs with `DONT_VALIDATE_SIGNATURE` (CLVM execution + conservation + structure) and the **L1 broadcast
target** (the Chia peer's `send_transaction`) verifies the signature against L1 constants. `auto_submit`
broadcasts only when a broadcaster is attached; there is NEVER an auto-broadcast in tests/CI (a real
mainnet broadcast is a separate, explicitly-gated live pass). Spend methods require the node-custodied
signer; a locked wallet returns an error. `multi_send` covers XCH payments (CAT payments via `send_cat`).

18.9a. **Method surface — offer suite + DID/NFT mint & transfer (served, #218).** `make_offer`,
`take_offer`, `view_offer`, `combine_offers`, `get_offers`, `get_offer`, `cancel_offer`, `create_did`,
`bulk_mint_nfts`, `transfer_nfts`, `transfer_dids`. Offers are built with the canonical `chia-wallet-sdk`
action system (`Spends`/`Action`/`RequestedPayments`/`Offer`): `make_offer` spends the offered coins into
the settlement puzzle and asserts the requested notarized payments (nonce = tree-hash of the sorted
offered coin ids), signs the maker side, and encodes the `offer1…` string; `take_offer` decodes the
offer, funds the requested payments from the wallet, signs the taker side, and returns the COMBINED
(maker + taker) signed bundle; `view_offer` decodes to the two-sided `OfferSummary` without settling;
`combine_offers` aggregates several offers' spend bundles into one; `cancel_offer` reclaims the offer's
still-cancellable offered coins back to the wallet. DID/NFT mint & transfer use the driver primitives
(`Launcher::create_simple_did`, one `IntermediateLauncher` per NFT + `Nft`/`Did` `TransferNft`
attribution, `Nft::transfer`/`Did::transfer`) — never hand-rolled CLVM. `bulk_mint_nfts` launches every
NFT off the minting DID coin and spends the DID once to acknowledge all attributions atomically, funding
the per-NFT launcher mojos + the fee from an XCH funding coin (Chia enforces conservation over the whole
bundle). Every built bundle is validated by `dig-clvm` (`DONT_VALIDATE_SIGNATURE`, as §18.9) before any
broadcast; `auto_submit` broadcasts only when a broadcaster is attached (never in CI). `make_offer`
persists the built offer to a local `offers` table when `auto_import` is set; `get_offers`/`get_offer`
read it back, `cancel_offer` marks it cancelled.

**Offer id.** Every offer id this surface reports or accepts -- `make_offer`'s returned id,
`take_offer`'s `transaction_id`, `get_offer`/`view_offer`/`cancel_offer`'s `offer_id`, and the primary
key of the `offers` table -- is `sha256(spend_bundle.to_bytes())` over the offer's DECODED, uncompressed
spend bundle, lowercase-hex-encoded without a `0x` prefix. This is the value Chia's `Offer.name()`, Sage
and dexie derive, so an id reported here reconciles against theirs, and it is independent of the bech32m
compression, so two encodings of one offer share an id. It is derived by `dig_offers::offer_id`, the
ecosystem's single definition. The id identifies the OFFER and not its offered coins: two offers funded
by the same coins but requesting different amounts are different offers and MUST carry different ids.
A wallet database written before this rule keys its offers by a value derived from the offered coin set
alone; those rows are re-keyed onto the canonical id when the database is opened, recomputed from the
`offer1...` string stored beside each key. Sage's per-endpoint `auto_submit` defaults are matched
(offers/mint/transfer default `false`; `make_offer.auto_import` defaults `true`).

18.10. **Signing + custody (C.6).** The node signs with its custodied seed only for node-class /
DIG-Browser callers (a `WalletSigner` over the wallet's synthetic p2 keys). Secret-touching endpoints
(`get_secret_key`/`generate_mnemonic`/`import_key`/exportMnemonic/revealSeed) stay 501'd + loopback+token
gated, NEVER reachable from a dapp/non-loopback origin. The MV3 extension self-custodies and does NOT use
the node's sign/spend path. (The paired-extension thin-client path that once inverted this —
the node custodying the key and signing on a caller's behalf — was removed by dig_ecosystem#1701, so
self-custody is again the only model, §18.20.)

18.11. **NFT/DID/CAT reconstruction.** A raw `CoinState` does not reveal a coin's asset kind — that lives
in the coin's puzzle, revealed only when its parent is spent. Reconstruction uncurries the parent spend
(via the `Nft`/`Did`/`Cat` driver parsers) to populate the `nfts`/`dids`/`nft_collections` tables and to
attribute CAT coins to their asset id (TAIL hash) in the `coins` table, which is what makes such a coin
visible to `get_cats`/`get_token` at all. Parent spends are fetched through a `LineageSource` (out-of-DB
lineage reads, B.5). Reads only. Neither reader becomes COMPLETE by this: a coin the replica never
ingested cannot be attributed by a pass over rows it does not hold, and a row whose parent could not be
read is left for a later pass.

The attributor is owned by the SUPERVISOR, which builds it from the subscription set it resolved for the
current attempt and threads it into the update loop; a supervisor with no lineage source attaches none,
and that absence MUST be honest rather than silent. The pass also runs ONCE after a completed catch-up,
so a replica that syncs and then receives no further pushes still attributes what it holds. The pass MUST
NOT run after a frame that was refused before any database write — otherwise an empty, already-refused
frame buys a whole-replica scan and a chain read per candidate row.

18.11a. **CAT discovery is not CAT authenticity — staged admission (#380, #394).** A `CoinState` carries a
parent, a puzzle hash and an amount, and **no hint**, so a wallet cannot recognise its own CAT coins from
the frame that delivers them. The node therefore DERIVES, for each address it follows and each asset id it
knows, the outer hash `cat_puzzle_hash(owner_p2, asset_id)`, and REQUESTS those hashes alongside the
addresses. Without this the peer never sends the wallet its CAT coins at all: a CAT coin does not sit at
its owner's address.

Requesting a derived hash is **discovery** and MUST NOT be read as ownership of that asset. The
derivation is injective — it commits to the CAT2 module, the asset id and the inner p2 together — but it
establishes only *"if this coin is ever spent, only this wallet can spend it, as this asset"*. It does
NOT establish that the coin is a unit of that asset, because `CREATE_COIN` is unconstrained in its
destination: anybody may place a coin at any puzzle hash, at a cost of one mojo per displayed base unit,
knowing nothing but the victim's public address. The same is true of a coin's HINT, which is likewise
chosen freely by whoever creates it.

**The coverage set and the admission set are different sets, and MUST NOT be the same value.**

- The **coverage** set is what the node asks a peer about: the addresses UNION the derived hashes. It
  determines what the wallet can SEE.
- The **admission** set is the wallet's own p2 addresses, and nothing else. It determines what may be
  written to `coins`.
- The union that produces the coverage set MUST be performed at the point that issues the request, and a
  derived hash MUST NOT be admissible even if one is supplied to that point as an address. One vector
  serving both roles is the defect this clause exists to exclude: it admitted every coin at a derived
  hash and typed it `asset_id: None`, which means XCH.
- The recorded coverage a replica claims (§18.13's authoritative-read routing) is the ADDRESS set, since
  that is the set its readers ask about.

The two states are held in **different tables**, and this separation is normative:

- A coin arriving at a derived hash, on ANY tier, MUST be written to `cat_admission_pending` and never to
  `coins`. This binds the peer catch-up, the peer frame path, and the point-read tier alike. The one
  exception is a coin already PRESENT in `coins` — one that has cleared promotion — whose later states,
  including its spend, MUST update `coins` as any other coin's would.
- A coin discovered by HINT rather than at a derived hash MUST be staged on the same terms. A hint is a
  claim its creator chose; admitting a hinted coin as an untyped row is the same fabricated-balance
  primitive reached without a peer.
- A coin sitting at one of the wallet's OWN p2 hashes is an ordinary XCH coin and is admitted directly.
  This is the only direct admission.
- A coin MUST enter `coins` only when a read of its parent spend reconstructs it as a CAT, and:
  - the reconstruction's coin id equals the staged row's; AND
  - where the coin was discovered at a derived hash, the reconstructed asset id and inner p2 hash both
    equal the ones the derivation predicted; OR
  - where the coin was discovered by hint and nothing was predicted, the reconstructed inner p2 hash is
    one the wallet controls.

  It is then written **fully attributed**, from the reconstruction's values and never from the
  derivation's or the hint's.
- `coins` retains exactly the semantics it has without this feature. No reader of `coins` — the balance,
  the spend-input selector, `get_cats`, the arrivals notifier — is required to apply a predicate to
  remain correct.
- Only the address set is presented to the arrivals notifier (§18.13), which reports payments to a user.

**Promotion** runs off the peer frame path, in the same out-of-band pass as §18.11 attribution:

- The frame path performs **zero** chain reads. Routing is a membership test against locally derived
  hashes, and the staging write takes no `LineageSource`.
- A pass reads at most `MAX_CAT_PROMOTIONS_PER_PASS` parent spends.
- **Promotion is terminal per VERDICT, not per coin, and the read cost is bounded by RATE.** A coin that
  is proven or disproven is never read again, because its staged row is deleted. A coin whose parent
  cannot be read reaches no verdict and MUST remain staged, so it will be read again — which is why a
  per-coin bound cannot be claimed. The queue is therefore served ordered by attempt count first and
  arrival order second, and a row is eligible only if it has not been read within
  `PROMOTION_RETRY_COOLDOWN`. Together these give: a row that never resolves can never hold the head of
  the queue against one that has never been tried, and the total read rate is bounded by
  `staged rows / cooldown` rather than by `cap` per pass.
- **A never-existing parent is NOT distinguished from an unreadable one, deliberately.** A source
  answers identically for a spend it has never heard of and one it is merely behind on, so a terminal
  refusal built on that answer would convert a brief outage into permanent erasure of a real coin. The
  cost is bounded instead of the cause classified.
- The four outcomes are distinct. **Proven** promotes into `coins`. **Resolved** — the parent read
  reconstructs the coin as an NFT or DID singleton owned by a p2 hash the wallet controls — writes it to
  `nfts`/`dids` and deletes the staged row. **Disproven** — a parent read that SUCCEEDED and refutes the
  claim — deletes the staged row. **Unavailable** — a read that could not be performed, or that the
  source answered emptily — leaves the row staged for retry, and MUST NOT delete it; treating an
  unavailable answer as a disproof would let a peer erase real money by withholding parent spends.
- **A proven non-CAT MUST NOT be refused.** *Resolved* and *Disproven* are separate outcomes because one
  says the derivation was true about something the CAT path does not itself handle, and the other says
  the derivation was a lie. Collapsing them makes a routing gap indistinguishable from a security verdict
  and deletes real assets terminally — the point-read tier is the only production path that reaches
  §18.11 reconstruction, so a wallet's NFTs and DIDs vanish and their chain reads are re-paid on every
  refresh. A singleton MUST NOT be written to `coins`: it carries no asset id, where absence means XCH.
- **A resolved singleton MUST be owned.** Admission requires the inner p2 hash the RECONSTRUCTION names
  to be one the wallet controls — the same test an unpredicted CAT is held to, and never the hint, which
  anybody may write.
- **A reconstructed singleton MUST reproduce its own coin.** The reconstruction is only a proof of
  ownership if the p2 hash it names is one the coin's puzzle is actually locked to, so §18.11
  reconstruction MUST recompute the singleton puzzle hash from the parsed info and refuse the coin unless
  it equals the child coin's own puzzle hash. Without this the preceding clause is vacuous for DIDs: the
  DID driver's read path takes the owner from the parent spend's `CREATE_COIN` memo hint and stores it
  verbatim, so anybody able to spend any DID could name any wallet as owner of their singleton. The NFT
  path needs no separate check — its child coin is derived from the parsed info, and the coin-id equality
  that path already requires commits to it.
- **Disproven covers five cases**, all terminal deletions: a coin already spent on chain (dropped without
  a parent read, since it can neither be counted nor selected); a staged row whose coin id does not bind
  its own parent, puzzle hash and amount; a reconstruction that disagrees with the derivation, or whose
  hint names an address the wallet does not control; a singleton owned by another p2 hash; and a coin
  whose parent spend reconstructs to nothing the wallet may hold at all.
- A promotion write MUST claim its staged row before writing the coin: the staging row is deleted first
  and the write proceeds only if exactly one row was removed, all in one transaction. Promotion spans a
  network round trip, and a reorg rollback inside that window must not be overwritten by a coin the
  replica has already decided to forget.
- A promotion failure MUST NOT propagate into the peer update loop. A chain read fails for reasons a peer
  can arrange, and an error reaching the update loop would end a live session.
- `cat_admission_pending` MUST be bounded, evicting oldest-first. The bound MUST delay and MUST NOT
  error: the staging write is on the frame path, and a peer that can fail a frame can deny a catch-up.
- Staged rows are rolled back with the coins they describe. A reorg deletes every staged row created
  above the fork and clears any spend recorded above it.

**Where promotion runs.** The promotion pass runs on BOTH tiers. On the point-read tier it is driven by
`refresh_tracked_coins`. On the peer path it is driven by the supervisor's `CatAttributor`, which runs it
once after a completed catch-up and again after every frame that actually WROTE something — so a staged
coin becomes spendable on the sync that delivers it rather than waiting for a point-read refresh. Until
#382 the peer path's attributor was constructed under `cfg(test)` alone and the production call site
passed a hard-coded `None`, so this tier existed and never ran; that is fixed, and the wording here is
the behaviour, not a licence — nothing above is relaxed by it.

**The stated failure mode is INCOMPLETENESS.** A real coin that cannot yet be proven is *absent* — not
counted as its asset, and in particular not counted as XCH, which `asset_id IS NULL` means and which
feeds coin selection. A wallet may under-report; it must never report a figure that is wrong.


18.11b. **A parent spend binds to the coin it was asked for.** A coin id is self-certifying —
`SHA256(parent ‖ puzzle_hash ‖ amount)` — so a `LineageSource` MUST check that the coin a spend answer
carries hashes to the coin that was requested, and MUST NOT return one that does not. Where it does not,
the coin is repaired from the coin record; where it still does not bind, the answer is NO LINEAGE rather
than a placeholder. This is a correctness requirement and not defence-in-depth: every CAT/singleton
driver derives its children's coin ids FROM that coin, so a placeholder makes `Cat::parse_children`
compute children matching nothing and the caller conclude the coin is not a CAT.

18.11c. **The attribution pass remembers its OUTCOMES, and distinguishes an absence from an outage.**
A coin's parent spend is settled chain history, so a row a pass RESOLVED and could not attribute answers
identically for ever. Those rows are ordinary: an NFT or DID coin row keeps `asset_id` NULL because the
reconstruction is written to its own table, and an odd-amount plain coin at the wallet's own p2 hash
reconstructs to nothing. A memory of failed LOOKUPS cannot cover them, because their lookups succeed — so
without an outcome mark each costs one outbound chain read per push frame for the life of the replica. A
row whose parent could NOT be read MUST NOT be marked: nothing was learned about it. The pass MUST
therefore cost work proportional to newly-arrived rows.

**A lineage answer distinguishes ABSENT from UNAVAILABLE, and the SOURCE must be able to tell them
apart.** "A source answered and there is no such spend" and "no source could be reached" MUST NOT be the
same value. Only an absence may be remembered or treated as a settled judgement; an unavailability is a
statement about this node's reachability and MUST be treated as *unknown*, so that a later pass asks
again.

The distinction MUST be carried by the chain READ, not merely by the enum. A source that reads spends
through an API which collapses "no such spend" into the same error as "the read failed" cannot produce an
absence at all, whatever its mapping says. The production source MUST therefore use an absence-aware,
corroborated read (`chia-query`'s `get_coin_spend_opt`), whose `Ok(None)` requires agreement across
independent sources and whose every transport failure, rejection and disagreement remains an error.

**A failed lineage read is NO LINEAGE, never an error.** An error propagates out of the attribution pass
and ends the peer session, which hands a denial of service to whoever made the read fail. The same
reasoning binds §18.11b's repair read, which fails to NO LINEAGE rather than propagating.

18.12. **Live broadcaster bring-up — real mainnet $DIG spends behind a config gate (#428).** The
node-custodied wallet BUILDS + SIGNS + VALIDATES spends (§18.9/§18.21) and the tip engine (§18.23)
reserves + caps them, but on the shipped node NO broadcaster is attached, so no `$DIG` moves. This
unit wires the LIVE path, gated so it is OFF by default (money-safe) and ON only by explicit opt-in.

- **Config gate (`enable_live_broadcast`, default OFF).** Sourced from
  `DIG_WALLET_ENABLE_LIVE_BROADCAST` (`1`/`true`/`yes`/`on` ⇒ enabled; **anything else, including
  unset, ⇒ OFF** — the OPPOSITE default to the dig.local toggle: money movement is never on by
  accident). OFF reproduces today's behaviour exactly (no broadcaster attached; a tip / sign-on-
  behalf / send cleanly reports unavailable and nothing is spent). ON assembles the live wiring.
- **Live wiring (`WalletService::build_with`).** When enabled, the bring-up builds ONE shared
  `chia_query::ChiaQuery` client (mainnet; decentralized peers + coinset.org fallback, §5.2) and
  attaches, all over that one client: a real `spend::ChiaQueryBroadcaster` (`chia_query::push_tx`),
  a `spend::ChiaQueryConfirmer` (on-chain confirmation poll), a `fallback::ChiaQueryLineage`
  (CAT/singleton parent-spend reads via `get_puzzle_and_solution`), and a `fallback::CoinsetFallback`
  read tier. A client-construction failure (offline / no peer reachable) is NON-FATAL and DISABLES
  live broadcast (logged) — a half-built client can never send.
- **The chain source MUST require nothing from the filesystem.** The peer TLS identity is generated
  in memory (`chia_query::TlsIdentity::Generated`, the `ChiaQueryConfig::default()`), never loaded
  from `~/.chia`. Chia full nodes accept any well-formed client certificate, so a file-backed
  identity buys nothing and costs correctness: the node runs as an OS service, whose account has no
  populated `~/.chia` (on Windows, `…\config\systemprofile`), so a file-backed identity made client
  construction fail and every `control.wallet.balance` answer `WALLET_NO_CHAIN_SOURCE` (§10). The
  coinset tier MUST also stay enabled, which keeps peers OPTIONAL: an empty peer pool degrades to
  keyless HTTP reads rather than failing construction outright. Requires `chia-query` ≥ 0.6.
- **A construction failure MUST be reported through the process log sink** (`tracing` ⇒
  `dig-logging`), never `stderr`: a service has no stderr attached, and this is the only account of
  why subsequent balance reads answer `WALLET_NO_CHAIN_SOURCE`.
- **Broadcaster split (no double-confirm).** The GENERAL wallet surface (send/offer/mint,
  `finalize_spend`/`submit_transaction`/`sign_coin_spends`) gets a `spend::ConfirmingBroadcaster`
  wrapping the raw broadcaster: it pushes to the mempool (the money boundary — a push error
  propagates) then BEST-EFFORT confirms on-chain (a miss/timeout is logged, NOT an error — the money
  already moved; the Sage responses carry no confirmation field). The TIP path gets the RAW
  broadcaster PLUS the confirmer directly, because it surfaces confirmation ITSELF in its ledger
  (below) and must not double-confirm.
- **Confirmation semantics (poll for a created coin).** `Confirmer::confirm(created_coin_ids)` polls
  `chia_query::wait_for_confirmation` for a created OUTPUT coin (a created coin with a non-zero
  confirmed height proves the spend was included in a block). `Ok(true)` = confirmed on-chain;
  `Ok(false)` = accepted into the mempool but not confirmed within the window (money moved —
  confirmation is asynchronous, NOT a failure). A confirmation READ error folds into `Ok(false)`:
  a failed read after a successful broadcast is never reported as a spend failure.
- **Tip ledger surfacing (confirm-before-marking-confirmed).** `WalletBackend::build_and_broadcast_dig_tip`
  returns `TipSpendOutcome::Broadcast { txid, confirmed }`. The engine reconcile (§18.23) maps
  `confirmed:true` ⇒ ledger status `Confirmed`, `confirmed:false` ⇒ `Pending` (txid recorded —
  broadcast, awaiting on-chain inclusion). Either way the persisted reservation blocks a same-day
  retry and its amount counts toward the caps, so a pending (unconfirmed) tip can NEVER enable a
  double-spend. An AMBIGUOUS broadcast error is still `Failed` (never retried that day, §18.23).
- **Coin selection over live-synced state (the wallet coin-DB sync contract).**
  `WalletBackend::refresh_tracked_coins` is a best-effort point-read sync that FEEDS coin selection:
  it reads the wallet's OWN coins from the fallback tier for every tracked p2 puzzle hash — XCH coins
  sitting AT the puzzle hash (`coin_records_by_puzzle_hashes`) AND CAT coins HINTED to it
  (`coin_records_by_hints`, since a CAT is hinted to the owner p2) — upserts them into the local coin
  DB (`unspent_coins`/`select_cats` read this), attributes each CAT to its TAIL by uncurrying the
  parent spend via the lineage source (so a `$DIG` coin, stored initially with `asset_id: None`, gains
  its asset id and becomes selectable), and marks the DB synced. It runs on the SPEND path: the live
  tip spender (and any node-custodied send) invokes it BEFORE selecting, so the spend builds over
  current chain state. Idempotent + non-destructive (upsert-only; a re-sync marks a now-spent coin
  spent so it drops out of selection). A sync failure is NOT a spend failure — selection then reports
  `NotExecutable`/insufficient-balance (retryable, never a false spend). A no-op when the chain transport cannot reach a
  source.
- **The chain transport is attached on EVERY install (dig_ecosystem#2376).** The wallet's chain
  READS (`control.wallet.balance`/`.coins`/`.peak`) and the push of an ALREADY-SIGNED bundle
  (`control.wallet.broadcast`) are served whether or not `DIG_WALLET_ENABLE_LIVE_BROADCAST` is set.
  That flag answers ONE question and keeps answering only it: may the node's OWN custodied wallet
  sign and send? It is still default-OFF. Whether the node may LOOK at the chain, and whether it may
  relay bytes somebody else signed, are different questions — neither needs a key and neither moves
  anything the node holds. Tying them together is what made a stock install answer
  `WALLET_NO_CHAIN_SOURCE` to every wallet read and unable to push at all.

- **The flag's SCOPE is one question; its EFFECT reaches two surfaces, and the node MUST say so
  (dig-node#437).** Enabling it also permits the mirror-coin collateral lifecycle to CREATE bonds,
  because that lifecycle's own switch — §25.7's `mirror_enabled`, held in `collateral.json` in the
  node's state directory — defaults to `true`, and the lifecycle's broadcaster is built only when
  this flag is on. So on an install that has never touched `collateral.json`, setting this flag is
  the last remaining step before the node commits operator `$DIG` as collateral automatically. Both
  effects MUST therefore be disclosed together at the point the flag is READ (`Config::from_env`),
  naming `mirror_enabled` and `collateral.json` as the way to disable the collateral half
  independently. Setting `mirror_enabled` to `false` stops CREATES only; reclaims continue, so the
  already-locked collateral is released rather than stranded.

  The push is served on every install but NOT unconditionally, because "somebody else signed it" is
  a claim about the bundle, not a property of the method: the node's own custodied wallet signs on
  request (`sign_coin_spends`), so a token holder could obtain a bundle signed by the node's key and
  hand it straight back for relay. While the flag is off, a bundle requiring a signature from ANY BLS
  public key the node custodies is refused with `WALLET_NODE_SPEND_DISABLED` (§10) — a single such
  spend refuses the whole bundle.

  The test is on KEYS, not on puzzle hashes, and the difference is the whole guarantee. A coin sits
  at its owner's standard p2 hash ONLY when it is bare XCH: a CAT sits at
  `CatArgs::curry_tree_hash(asset_id, p2_hash)`, and singleton/NFT/DID coins wrap the owner puzzle
  again — while signing matches the REQUIRED key and ignores where the coin sits. A guard comparing
  puzzle hashes would therefore relay the node's own $DIG, which is a CAT. The required keys MUST be
  extracted with the same derivation the signer decides on, so the guard covers every puzzle wrapper
  present or future and cannot drift from what it guards. A bundle whose conditions cannot be
  evaluated MUST be treated as custodied.

  The custodied set is the union of the loaded signer, every signer this process has loaded (the
  no signer is ever resident by push time), and the custody manifest's PERSISTED
  public keys — non-secret, readable while every wallet is locked, and covering the whole covered
  window in BOTH the unhardened and hardened trees rather than the index-0 receive address alone.
  The window is sized by §18.7a, so it is not a constant. Merely WATCHED puzzle
  hashes are NOT in it: the node holds no key for those, and refusing them would block a legitimate
  third-party push. Without this check the flag would be decorative on the one path that matters.

  The transport's client is built on FIRST USE, so an idle node still makes no chain call, and a
  build failure is NOT cached: a node that was offline when first asked can answer when its network
  returns. A failure to reach the chain is always an error, never an empty result (§10).

- **Canonical query hex.** All coin-record queries into `chia_query` (the fallback tier: peers +
  coinset.org) MUST pass hashes/hints as lowercased **`0x`-prefixed** hex. The coinset RPC matches
  ONLY `0x`-prefixed hex (the peer tier tolerantly strips an optional `0x`); a bare-hex query silently
  reads back zero coins. `refresh_tracked_coins` builds tracked puzzle hashes with bare `hex::encode`,
  so the `CoinsetFallback` adapter normalizes them to the `0x` form at the query boundary (the DB and
  internal comparisons stay bare-hex). Omitting this normalization is the live "have 0 $DIG" failure
  (#430): the mock/peer paths accept bare hex, so it surfaces only when a bring-up falls through to
  coinset.
- **No live-funds e2e (removed with node-side custody).** The env-gated mainnet `$DIG` tip test drove
  its spend by IMPORTING a funded mnemonic into node custody, which dig_ecosystem#1701 removed — a node
  can no longer hold a seed, so the test's premise is gone along with the capability. **CI never
  broadcast to mainnet** and still does not: automated tests use the `chia-sdk-test` simulator (real
  consensus incl. BLS) or the recording `MockBroadcaster`/`MockConfirmer`. A future live pass MUST get
  its signature from outside the node.

18.12a. **Deferred to follow-on units.** The off-chain NFT data-blob/CHIP-0015 metadata fetch
(`get_nft_data` returns on-chain fields; the metadata JSON surfaces when fetched), `exercise_options`
(§18.15 — a documented, non-silent follow-on), and real image-derived theme content (§18.16 — this
backend stores a placeholder). The point-read live sync above populates the DB for the spend path;
the richer live direct-peer SUBSCRIPTION sync loop (§18.6) — feeding the shared `EventBus` from real
chain `coin_state_update` pushes for continuous wallet-data reads — remains the follow-on integration
(until it is spawned, wallet-data reads outside a live spend use the fallback tier / point-read sync).

18.13. **Security.** Both listeners bind loopback only. The mTLS listener enforces the shared-cert mutual
TLS. Multi-peer sync is a correctness/censorship property (never collapse to one peer). Reads tolerate
unknown/forward-incompatible fields (additive, §5.1 spirit). Spend submission is validated via `dig-clvm`
before broadcast (fail-closed) and never auto-broadcasts without an attached broadcaster.

18.14. **`SyncEvent` stream (design A.9, #205 PR4).** An in-process [`crate::sage::events::EventBus`]
(a `tokio::sync::broadcast` channel) the direct-peer sync loop (§18.6) publishes lifecycle events to:
`start{ip}` (sync begins on a peer), `subscribed` (puzzle-hash subscription acknowledged),
`puzzle_batch_synced` (once per initial-catch-up batch applied), `coin_state` (a `coin_state_update`
applied), `stop` (the peer connection ended). Streamed over `GET /events` (Server-Sent Events) on BOTH
transports (the shared router, §18.1) — the `event:` field is the Sage `type` tag, `data:` is the
event's JSON. A best-effort push channel: publishing with zero subscribers is a no-op, and a lagging
subscriber (broadcast-channel overflow) simply misses the gap rather than erroring the stream —
`get_sync_status` polling remains the authoritative source of truth regardless of whether anything is
subscribed. `derivation`/`transaction_failed`/`cat_info`/`did_info`/`nft_data` are defined on the wire
(byte-parity with Sage's tagged union) but not yet published by any producer — reserved for the
respective follow-on work.

18.15. **Option-contract suite (design A.5, #205 PR4).** `get_options`/`get_option` (DB reads, paginated/
sorted/filtered like `get_nfts`), `mint_option`/`transfer_options` (real `chia-wallet-sdk`
`OptionLauncher`/`OptionContract` driver builders — never hand-rolled CLVM, §4.1) are served.
`mint_option` in this backend mints an **XCH-underlying** option only (the underlying lock coin holds
plain XCH); the strike may be XCH or a CAT (a pure enum tag with no extra coin-construction cost at mint
time — the exerciser funds it later). A CAT/NFT-underlying mint returns a clear `400` naming the
limitation, never a mis-built spend. `exercise_options` is accepted on the wire but returns a clear,
named `500` (`crate::sage::options::exercise_options_unimplemented`) — exercising requires tracking the
underlying-lock coin's OWN lineage (a derived, non-HD puzzle hash outside the wallet's ordinary
subscription set) plus the `MipsSpend`/merkle-proof machinery `OptionUnderlying::exercise_spend` needs; a
tracked follow-on, not a silent gap. The `OptionRecord` wire shape (`launcher_id`/`amount`/
`underlying_asset`/`strike_asset`/`name`/`created_timestamp` alongside the coin/visibility/expiration
fields) is verified field-name-identical against the pinned v0.12.11 generated OpenAPI (§18.19) — an
initial guess used `option_id` instead of the real `launcher_id`, caught and fixed by that vector.

18.16. **Record-update actions + the theme store (design A.5, #205 PR4).** `resync_cat` (clears a CAT's
cached display metadata, forcing a re-fetch — balance/coins untouched), `update_cat` (persists a
caller-supplied `TokenRecord`'s display metadata; requires `asset_id`), `update_did`/`update_option`/
`update_nft`/`update_nft_collection` (name/visibility, patching both the indexed DB column and the
stored wire-record JSON so subsequent reads reflect it immediately), `redownload_nft` (clears cached
off-chain metadata JSON, forcing a re-fetch), `increase_derivation_index` (raises a per-tree derivation-
index FLOOR so `get_sync_status`/`get_derivations` report at least the requested coverage — never
lowers an existing floor; requires `hardened` and/or `unhardened` be requested). The theme store
(`get_user_themes`/`get_user_theme`/`save_user_theme`/`delete_user_theme`, Sage-desktop-UI origin,
design Part F MAY/N-A) is DB-backed, keyed by NFT id. **Verified against the generated OpenAPI
(§18.19):** the real `save_user_theme` request carries ONLY `nft_id` — Sage derives the theme from the
NFT's own artwork (color extraction) rather than accepting caller-supplied content (an initial guess
added a `theme: String` field, caught and fixed). This backend has no image/color-extraction pipeline,
so `save_user_theme` persists a fixed placeholder (`crate::sage::themes::DERIVED_THEME_PLACEHOLDER`)
rather than a real derived theme — `get_user_theme(s)` still correctly reports "is this NFT themed",
just not a real color scheme; real derivation is a tracked follow-on.

18.17. **Network / peer / sync settings (design A.5, #205 PR4).** `get_peers`/`add_peer`/`remove_peer`
are DB-backed: `add_peer` persists a user-managed entry at the standard Chia full-node port (design
B.1, `8444`) surviving restarts (mirroring Sage); `remove_peer{ban:true}` keeps the row but excludes it
from the DIALLING read (`get_peers` still enumerates it, flagged); `peak_height` reports `0` until live
per-peer telemetry is wired to the sync loop -- never fabricated, and reported as the INTEGER Sage sends
so a strict parity client keeps parsing. The unobserved-vs-genesis distinction is drawn at the control
boundary instead (`control.chiaPeers.list` maps `0` to `null`), which is this node's own surface.
`add_peer`/`remove_peer` are MASTER-TOKEN TIER on this surface too (§7.12): they are the parity aliases
of `control.chiaPeers.add`/`.remove` and reach the identical writer. `set_discover_peers`/`set_target_peers`/`set_delta_sync`/`set_delta_sync_override`/
`set_change_address` persist to a `network_settings` row. `set_network`/`set_network_override` both set
the same stored network override (this backend tracks one active wallet key; a genuine per-fingerprint
override is a follow-on for multi-key support). `get_networks`/`get_network` report the two networks
this backend can sync against (design Part B): mainnet and testnet11. `NetworkKind` is a 3-variant enum
(`mainnet`/`testnet`/`unknown`) — verified against the generated OpenAPI (§18.19); an initial guess had
only 2 variants, caught and fixed. The real Sage `Network`/`NetworkList`/`get_network`/`get_networks`
response schemas are opaque (untyped `object`) in the generated OpenAPI, so this backend's `Network`
shape (`name`/`ticker`/`address_prefix`/`precision`/`default_port`) is a best-effort, not byte-verified,
representation — documented as such.

18.18. **dig-keystore seed migration (design C.2, #205 PR4).** The wallet's on-disk seed file
(`seed_path()`, §16) is now encrypted at rest via the `dig-keystore` crate's `opaque` container
(Argon2id + AES-256-GCM, versioned/magic-tagged/CRC-guarded — the SAME primitives the bespoke
`digstore_chain::seed` format used, now consolidated onto the ecosystem's canonical keystore crate,
Appendix B) for every NEW write (`crate::seed_store::encrypt_seed`). Reads accept EITHER format: the
on-disk magic (`DIGVK1`/`DIGLW1`/`DIGOP1` = a `dig-keystore` container; anything else = the legacy
layout) selects the decoder, so a seed file written before this migration keeps opening
(`crate::seed_store::decrypt_seed`) — proven by a golden-fixture test that encrypts a mnemonic with the
ACTUAL legacy `digstore_chain::seed::encrypt_seed` and asserts the new unified reader still recovers it.

18.19. **Generated-OpenAPI conformance vector (design A.10, #205 PR4).** `sage-cli` (a pure CLI/RPC
crate, no Tauri/desktop dependency) was built from the pinned `xch-dev/sage` `v0.12.11` tag and
`cargo run --bin sage rpc generate_openapi` run to produce the golden vector, committed as
`crates/dig-wallet/tests/vectors/sage-openapi-v0.12.11.json` (100 paths, matching the design's method
count) — no build step is needed to re-derive it; re-pinning to a newer Sage tag regenerates it the same
way. `crates/dig-wallet/tests/conformance.rs` asserts every served method has a real path in it, and
cross-checks representative request/response schemas field-name-identical against it — this caught the
three real drifts documented in §18.15/§18.16/§18.17. The hand-authored `sage-endpoints-v0.12.11.json`
(method-name-only) vector from #215 remains as a lighter first check.

18.20. **The node does NOT custody user wallets (dig_ecosystem#1701).** It once did: it generated or
imported BIP-39 seeds, encrypted them at rest, unlocked them into an in-memory `WalletSigner`, and signed
+ broadcast on a paired caller's behalf. The #1500 ratification (2026-07-22T03:27:48Z) settled that it
must not, and the surface has been REMOVED. A node MUST NOT provide any method that generates, imports,
restores, unlocks, deletes, reveals, or signs with a user's seed, on any transport.

This is STRUCTURAL, not a policy a future change can quietly relax: no path
through `crate::sage` reads a `.seed` file, decrypts one, derives a secret key, or constructs a
`WalletSigner` from user material. The user's key lives in the user application, and `dig-account`'s
`PolicyAuthorizer` is the only enforcing custody gate for it.

**§908 is satisfied on BOTH planes.** The second surface — the self-origin wallet UI in `crate::lib`
(§16.3) — has also been removed (dig-node#327). `POST /api/generate`, `/api/import`, `/api/unlock`,
`/api/lock`, `/api/export`, `/api/send`, `/api/balance`, `/api/stores`, `/api/stores/history`,
`/api/wallet/pubkey` and `/api/wallet/source` no longer exist, and the CHIP-0002 dapp signer no longer
has a local arm: `wc_dispatch` answers only the keyless handshake methods (`chip0002_chainId`,
`chip0002_connect`, `chip0002_getMethods`) and forwards every other method to the user's Sage wallet over
the WalletConnect requester session. There is no wallet-source setting to route a method back into the
process, because there is no second route to select.

This too is STRUCTURAL rather than a policy check. The process holds no unlocked-session state — the
field is gone from `AppState` — so a signer would have no material to read; and `seed_store::encrypt_seed`
is `#[cfg(test)]`, so a production caller that sealed a user seed would not compile. A node MUST NOT
provide any method that generates, imports, restores, unlocks, deletes, reveals, or signs with a user's
seed, on any transport, and no code path remains that could.

**A pre-existing seed stays recoverable, offline.** A file already written under `seed_path()` by an
earlier build is NOT read, used or deleted by this one. It is recovered with `dign wallet export-seed
[--path <file>]`, which decrypts under the user's own password in-process and prints the phrase to the
console. That command reads BOTH on-disk formats (the current `dig-keystore` container and the legacy
`digstore_chain::seed::EncryptedSeed` layout) and takes an explicit path, so a file written under a base
directory this build no longer resolves is still reachable. It has no network surface: a served export
would add a permanent seed-exfiltration capability in order to solve a one-time migration. `GET
/api/status` reports `"custodied"` while such a file exists — `"delegated"` otherwise — and both UI
surfaces point at that command rather than revealing anything in the browser.

**What remains is a read.** `crate::sage::custody::WalletCustody` reads ONE non-secret file,
`<config_dir>/wallets/index.json`, and answers two questions for the chain-sync supervisor (§18.6):
whether ANY wallet is enrolled on this device (`any_wallet`), and which standard-layer PUBLIC keys it
covers (`custodied_public_keys`). Those keys become subscription addresses and are what the push guard
(§18.12) checks a pre-signed bundle against. Neither answer requires — or can obtain — a key.

18.20a. **On-disk layout, read-only (#427, reduced by dig_ecosystem#1701).** A pre-existing install's
wallets live under `<config_dir>/wallets/`: one opaque `dig-keystore` container per wallet at
`<config_dir>/wallets/<id>.seed`, plus a non-secret JSON manifest `<config_dir>/wallets/index.json` =
`{ "active": "<id>"|null, "wallets": [{ "id", "address"?, "label"?, "created_ms", "public_keys"? }] }`.
A legacy single seed at `<config_dir>/wallet-seed.bin` (the #370 layout) is adopted under the reserved id
`default`.

A node MUST read this layout and MUST NOT write a new wallet into it. The manifest is still self-healing —
a missing or corrupt `index.json` is rebuilt from the seed files present, each adopted with no public keys
— so an enrolled wallet is reported as enrolled even when no address is derivable from it. That state is
distinct from "no wallet at all" and MUST stay distinguishable (dig_ecosystem#2609): the first means the
node is not following coins it should be, the second is the honest all-clear.

Since nothing can enrol a wallet, the set can only shrink. The measured population of installs holding one
is ZERO (dig_ecosystem#1701 step 2, four machines on two independent instruments), so in practice every
node reports no wallet.

18.21. **The node does not sign or broadcast on a user's behalf.** _Removed by dig_ecosystem#1701._ The
sign-and-broadcast-for-a-paired-caller path required a node-custodied signer, and there is none. A node
MUST NOT sign a spend with user material. Relaying an ALREADY-SIGNED bundle is a different capability and
survives (`control.wallet.broadcast`, §18.12): it moves bytes a caller signed elsewhere and needs no key.
Whether the node may spend its OWN money remains a separate, default-OFF decision
(`DIG_WALLET_ENABLE_LIVE_BROADCAST`, §18.12), unrelated to user custody.


18.22. **Served on the shipped node + runtime signer load + custody dispatch (#368/#369).** The
`WalletBackend` is BUILT and SERVED by the shipped `dig-node` (§18.1): the `POST /{method}` HTTP mirror on
`9778`, the mTLS `9776` sibling listener, and the bidirectional `/ws` transport (§4.8) all dispatch to the
one live backend.

- **No runtime signer load.** `current_signer` resolves ONLY the bring-up-injected signer
  (`with_signer`), which no shipped build attaches — it exists for the simulator/test path. A shipped node
  therefore has no signer at all, and every method that needs one refuses (dig_ecosystem#1701, §908).
  A refusal MUST name the state the node is actually in and MUST NOT report the wallet locked merely
  because no signer resolved: the two are independent here, so an UNLOCKED wallet would be told to
  unlock, and node-managed unlock was removed (§18.24) so no unlock would help. The tip path
  (§18.23) states the three observable cases separately.
- **No custody dispatch.** `wallet.*` and `auth.*` reach no handler; the wallet gate refuses the prefixes
  outright (§7.12) and neither appears in discovery. The attached `WalletCustody` is a read (§18.20) that
  contributes PUBLIC addresses to the subscription set and to the push guard.
- **Sync-status snapshot.** `WalletBackend::sync_status()` derives the `{ state, peak_height, target_height }`
  tri-state (`SyncStatus`, `crate::sage::events`) from the wallet DB — `synced` iff the initial catch-up
  completed, else `syncing`; it is the body the `/ws` transport pushes (§4.8) and re-pushes on transition.

## 18.23. Tipping subsystem — owner lookup, auto-tip policy engine, $DIG spend, tip ledger (#377/#378)

The node OWNS tipping: it holds the wallet/keys and builds+signs+broadcasts the $DIG tip spend; a thin
client (the extension, #379/#380) only CONFIGURES + DISPLAYS it over the WS wallet/control transport
(§4.8). The client NEVER hand-rolls a tip spend. Implemented in `crate::sage::tipping`
(`TippingEngine`), attached to the served `WalletBackend` (`with_tipping`).

**Owner-PH lookup.** A store's on-chain OWNER puzzle hash is resolved from its CHIP-0035 singleton
(the launcher id) via `digstore_chain::singleton::sync_datastore(...).info.owner_puzzle_hash` — the SAME
DataStore parser the node uses for store sync (never re-parses a singleton by hand). The result is
cached per store. The chain client is a `digstore_chain::coinset::ChainReads` (coinset.org) behind the
`OwnerResolver` seam; a `chia-query`-backed `ChainReads` (decentralized peers + coinset fallback — the
substrate that already backs the coin-read fallback tier, §18.5) is a drop-in.

**Config (`tipping-config.json`, persisted, durable atomic write).** `{ creator: AutoTipPolicy, dev:
AutoTipPolicy, daily_total_cap, fee }` where `AutoTipPolicy = { enabled, dig_amount, mode, per_site_cap,
per_site_overrides }` and `mode ∈ { per-site-per-day, daily-budget }`. Amounts are $DIG base units (1
$DIG = 1000 base units, `DIG_DECIMALS = 3`). **Both creator and dev auto-tip are DEFAULT-ON** (#377) —
each has a real recipient (the on-chain-resolved store owner / the DIG treasury), so default-on is safe
paired with the honest-default disclosure + one-click-off (§6.0, #207).

**DIG dev-account daily tip.** The SAME engine, a SEPARATE toggle. Recipient = the **canonical DIG
treasury inner puzzle hash** — the EXISTING byte-identical shared contract that receives every
per-capsule $DIG payment (`digstore_chain::dig::treasury_inner_puzzle_hash()`, decoded from
`TREASURY_ADDRESS` `xch1a37rq3cgcl2ecpudttsf35x75qzdan68lgw2l6ajvmqs44jxdn5qv6pk3y` =
`ec7c304708c7d59c078d5ae098d0dea004decf47fa1cafebb266c10ad6466ce8`; mirrored byte-identical in chip35 +
dighub-core). It is sourced from the shared contract (NEVER re-hardcoded, so a payment-critical value can
never drift into a divergent copy) and is a REAL recipient — so the dev tip is DEFAULT-ON with a small
default daily amount + the same hard caps. Its CAT spend targets this inner PH exactly as the per-capsule
payment does (`Cat::spend_all` CAT-wraps it).

**Money-safety invariants (real mainnet $DIG) — FAIL CLOSED.**
- **Hard caps.** A per-site/day cap (in `per-site-per-day` mode) AND a daily total cap spanning creator +
  dev. Reserved (`Pending`), `Confirmed`, AND ambiguous-`Failed` amounts all count toward the caps, so an
  in-flight or unknown-outcome tip can never be double-counted into an over-spend. A tip that would exceed
  a cap is SKIPPED (`over-per-site-cap` / `over-daily-cap`), never trimmed-and-sent.
- **Crash-safe idempotency.** At most ONE auto tip per `(kind, owner/site, UTC-day)`. The ledger
  reservation (a `Pending` entry) is persisted to `tip-ledger.json` IMMEDIATELY BEFORE the broadcast
  (the only money-moving step). A crash at any point leaves ≤1 reserved entry for that key; on restart the
  engine (re-loaded from the ledger file) treats the key as already tipped and SKIPS — erring toward
  under-tipping, never a double-spend. A definitively PRE-broadcast failure (`TipSpendOutcome::NotExecutable`
  — no signing key / not-yet-synced / insufficient $DIG) rolls the reservation back (retryable); an
  AMBIGUOUS broadcast error keeps it as `Failed` (never retried that day).
- **A signer-absence refusal names its own state (#410).** When no signing key resolves, the
  `NotExecutable` reason MUST be exactly one of the three published `crate::sage::tipping::refusal`
  constants, chosen by what the backend can OBSERVE: no custody view attached at all
  (`NO_SIGNER_CONFIGURED`), a custody view holding an enrolled wallet whose sealed seed this node
  cannot open (`WALLET_ENROLLED_BUT_UNOPENABLE`), or a custody view holding no wallet
  (`NO_WALLET_ENROLLED`). The three MUST be distinct strings and none MUST assert that the wallet is
  locked, because the signer is absent on the shipped node whether or not any wallet is locked, and
  §18.24 removed the unlock such a message would send the reader after. `Orphaned`
  (`crate::autoseed::BootstrapState::Orphaned`) is deliberately NOT among them: it is decided at
  bootstrap from paths the backend does not hold, so reporting it here would be a guess of the same
  kind this clause forbids. The refusal is PRE-broadcast in every case — no bundle is built, signed
  or sent.
- **Fail-closed on unreadable persisted state.** Load distinguishes an ABSENT file (a genuine first run:
  config → DEFAULT-ON, ledger → empty) from a file that is PRESENT but unreadable/unparseable
  (locked / corrupt / truncated / forward-incompatible). A present-but-unreadable **ledger** POISONS the
  engine — EVERY tip (auto + manual) and config mutation is REFUSED (skip `state-unreadable: …`) until the
  operator resolves the file and restarts — so a corrupt ledger can NEVER reset the cap + idempotency
  accounting to "empty → tip freely" (an N×cap over-spend / same-day double-spend). A present-but-unreadable
  **config** never silently falls back to the DEFAULT-ON default: it fails closed to DISABLED (never
  re-enables an auto-tip the user turned off) and also poisons. `unwrap_or_default()` on the persisted read
  is forbidden.
- **Durable writes.** `tip-ledger.json` / `tipping-config.json` are written to a temp file that is
  `fsync`ed, atomically `rename`d into place, then the parent directory is `fsync`ed (best-effort) — so a
  crash/power-loss can never leave a truncated/zero-length ledger that would then trip the fail-closed
  read path.

**The $DIG spend.** `WalletBackend::build_and_broadcast_dig_tip` selects input $DIG CAT coins
(`asset_id = digstore_chain::dig::DIG_ASSET_ID`) + XCH fee coins, builds via the canonical
`chia-wallet-sdk` `Cat::spend_all` (`spend::build_cat_send` — never hand-rolled CLVM), validates with
`dig-clvm` (`DONT_VALIDATE_SIGNATURE`, §18.9, fail-closed), signs with the node-custodied `WalletSigner`,
and broadcasts through an injected `Broadcaster` (the engine passes its own — so enabling tips does NOT
enable live broadcast for the whole wallet surface). Unattended auto tips need NO per-op user interaction:
the standing config consent (enabled + caps) IS the authorization (the honest-default model, §6.0/#207).
CI NEVER broadcasts to mainnet — tests drive the `chia-sdk-test` simulator + a recording `MockBroadcaster`.

**Method surface (`tip.*`, dispatched by `WalletBackend::dispatch`).** Reads are OPEN; mutations are
paired-token gated (§7.12, `wallet_authz::GATED_WALLET_MUTATIONS`):
- `tip.get_config` (read) → the `TippingConfig`.
- `tip.set_config` (gated) → replace + persist config; returns the stored config.
- `tip.get_ledger { since_ts? }` (read) → the ledger, newest first (each entry `{ id, recipient_ph,
  store_id?, dig_amount, ts, day, txid?, trigger: auto|manual, kind: creator|dev, status:
  pending|confirmed|failed }`).
- `tip.notify_consumed { store_id }` (gated) → run the creator auto-tip for a consumed store.
- `tip.dev_tick` (gated) → run the dev-account daily tip (pays the DIG treasury shared contract).
- `tip.manual { store_id }` (gated) → one-tap manual tip to the store's owner (explicit consent: NOT
  bounded by the auto caps, NOT subject to the once-per-day idempotency).
Each returns a `TipOutcome` — `{ result: "tipped", txid, dig_amount, recipient_ph }` or `{ result:
"skipped", reason }` (stable reason tokens: `disabled`, `owner-unresolved`, `already-tipped-today`,
`over-per-site-cap`, `over-daily-cap`, `state-unreadable: …`, `wallet-unavailable: …`,
`spend-failed-not-retried: …`).

**WS push (§4.8 extension).** When a tip is recorded the engine publishes a `TipEvent` on a DEDICATED
`TipEventBus` (kept OUT of the Sage-parity `SyncEvent` union so tip events never leak into the `GET /events`
Sage stream). Each `/ws` session forwards it as a `{ "type": "tip", "tip": <ledger-entry> }` push frame,
alongside the `sync_status` + `event` frames.

## 18.24. Node-managed unlock authentication — REMOVED (dig_ecosystem#1701)

The `auth.*` namespace gated a node-custodied signer: `auth.unlock` granted a read-only session,
`auth.sign_unlock` decrypted the seed for exactly one signature, and TOTP/passkey enrolment backstopped a
stolen password. It existed because the node held the user's spend key.

It no longer does (§18.20, §908), so the gate has nothing to gate and has been removed along with the
custody it protected. A node MUST NOT serve any `auth.*` method; the wallet gate classifies the prefix as
retired and denies it before consulting a token (§7.12), and it appears in no discovery artifact.

The properties this section used to specify — a key not resident between signatures, one grant authorizing
exactly one signature, a factor re-verified before it can be replaced — are all statements about holding a
user key. Not holding one is the stronger guarantee, and it is the one the node now makes.


## 18.25. Machine identity key at rest (dig_ecosystem#2168)

The node's §21.9 identity seed is the node **authenticating itself**: it derives the BLS key the
CA-signed `NodeCert` is bound to, and therefore the stable `peer_id = SHA-256(SPKI DER)` the peer
network knows the node by (§19). It is **NOT user custody** — §18.20 retired the node-side user
custody plane and MUST NOT be read as retiring this. A user's spend key never enters the node; this
key never leaves it.

**At-rest format.** The seed MUST be sealed in a `dig_keystore::opaque` `DIGOP1` container
(AES-256-GCM, Argon2id) under a 32-byte CSPRNG **device key** — the same container and key model
§16.4 specifies for the wallet host, so the node has ONE at-rest primitive rather than two. The
node MUST consume `dig-keystore` with its `custody` feature OFF, so the user-custody API is not
nameable from the engine (dig-keystore `SPEC.md` §18.2). A raw, unsealed seed file MUST NOT be
written.

**File layout.**

| Path | Contents |
|---|---|
| `<identity_dir>/machine-identity.dks` | the sealed `DIGOP1` seed blob |
| `<identity_dir>-device/device.key` | 32 raw CSPRNG bytes, no header |

Both are owner-only **on Unix** — mode `0600` set at `open` time, not by a later `chmod`. **On
Windows both inherit the profile ACL**; neither the keystore's `FileBackend` (whose
`enforce_owner_only` is `#[cfg(unix)]`) nor this node installs an explicit `D:P(A;;FA;;;<user>)`
DACL for them. §16.4's wallet files DO install that DACL. A surface MUST NOT claim owner-only
enforcement for the machine key on Windows — it MUST state the floor the running platform actually
gives it. Bringing Windows to §16.4's floor is recorded as finding 3 on
https://github.com/DIG-Network/dig_ecosystem/issues/2168 and is NOT satisfied by this section.

The device key is a raw file rather than a keystore record deliberately: it is written with
`create_new`, and that atomicity is load-bearing (below). `FileBackend::write` is tmp-plus-rename,
i.e. REPLACE semantics.

`<identity_dir>` is `$DIG_IDENTITY_DIR`, else `<config_dir>/dig` — byte-identical to the path the
legacy plaintext seed used, so migration finds the existing identity. The device directory is a
**SIBLING**, never a child: that separation IS the partial-exfiltration boundary (§16.4), and it is
the only confidentiality this key has on a host with no hardware provider. A copy of the identity
directory alone MUST NOT yield the seed.

**Migration.** On first start after upgrade, a legacy plaintext `<identity_dir>/identity_key.bin`
MUST be adopted as the seed — never replaced by a fresh one, which would change the node's
`peer_id` — sealed, and only then removed. The plaintext file MUST NOT be removed before the sealed
copy has been read back from storage and compared. The legacy existence check is bound by the same
`try_exists` rule above: an unreadable legacy path MUST refuse, not mint.

**`identity_key.bin` is a CROSS-TOOL artifact.** `digstore_remote::identity` owns the same path and
the co-installed `digs` CLI reads it. Removing it therefore causes `digs` to mint a fresh
**plaintext** seed into the same directory on its next run, silently changing its §21.9 operator
identity — the node's identity is preserved, `digs`'s is not. The removal is still correct for the
node, whose seed must not remain in plaintext; the coherent end state is `digs` reading the sealed
store through this same module, recorded as finding 2 on
https://github.com/DIG-Network/dig_ecosystem/issues/2168 and NOT satisfied by this section.

**Existence MUST be answered by `try_exists`, never `Path::exists`.** `exists()` is
`fs::metadata(..).is_ok()`, so it reports a locked, permission-denied or otherwise unreadable path
as ABSENT — and the next thing the node does with an absent answer is MINT, which overwrites both
halves. The node MUST distinguish present / absent / **undeterminable** and MUST refuse on the
third rather than minting. This matters more after sealing than before it: the artifact this
replaced was a single plaintext file, so the same misread produced a recoverable duplicate; with
two coupled sealed halves it destroys the identity permanently.

**The device key MUST be installed with `create_new`, and an existing one ADOPTED.** Two starts can
overlap — a service restart racing the outgoing process, or a manual run beside the service. With
replace semantics they can leave one process's device key beside the other's blob: a matched pair
that no longer matches, which the no-re-mint rule below then prevents from ever self-healing. The
OS atomic test-and-set makes that state unreachable rather than merely unlikely, because exactly
one racer creates the key and the other adopts it, so both seal under the same key.

**The three-valued rule binds EVERY read on this path, including the device key.** A device key
that is present but momentarily unreadable — an on-access scanner holding it with `share_mode(0)`,
a profile sync, a busy volume — MUST NOT be reported as a mismatch. That is the read whose failure
message carries a destructive instruction, so misclassifying it tells an operator to delete a
present, intact identity. An undeterminable read MUST say *retry* and MUST NOT propose removing
either half.

**A mismatched or missing device key MUST be reported as a NAMED state** that identifies both
halves by path and states the remedy. It is the one state the no-re-mint rule cannot heal, so a
bare decrypt failure leaves an operator with a permanently dead node and nothing to act on. The
message MUST separate what is **known** (the two do not currently match) from what is
**undetermined** (which half is wrong, and whether the matching half still exists), per
dig-keystore `SPEC.md` §17.5b's discipline, and MUST offer restoring before the irreversible
option.

**A stored seed that will not open is an ERROR, never a re-mint.** The node MUST report the failure
and continue with authenticated §21 sync disabled. Minting over it would hand the node a new
identity in exactly the situation where the real key is most likely still intact on the machine
that sealed it.

**Binding to the host's trusted component.** The node MUST walk the platform ladder when opening
its machine keystore — Windows TPM 2.0, Apple Secure Enclave, Linux TPM 2.0 — and MUST NOT report
`Software(NotRequested)`, which asserts that no binding was ASKED FOR. It MUST request a policy
that refuses to report an uninspectable host as an absent one, and it MUST NOT let that refusal
prevent the keystore opening: the machine key is on the boot path, and a node that cannot construct
it cannot serve the peer network. A host whose trusted component cannot be inspected therefore
degrades to the software floor, and the node MUST report the probe's own reason for that degrade
rather than a confident `NoHardwarePresent`.

**Reporting protection honestly.** A surface reporting what protects the key MUST read the
**blob's** tier, not the host's — a hardware-capable host does not retroactively protect bytes already at rest. On a blob
this host cannot open, the node MUST NOT make a recovery promise: per dig-keystore `SPEC.md`
§17.5b the envelope records a hardware *class* and carries no device identity, so the same error is
returned for a blob copied off its machine (recoverable) and for the original machine with its
trusted component wiped (permanent). The node MAY state that condition; it MUST NOT resolve it.
### 18.25a. What sealing the seed does NOT cover: the derived peer key (dig-node#343)

Sealing the seed (§18.25) protects the ability to **re-derive** the node's identity. It does NOT
protect the **derived** material, and a surface MUST NOT imply that it does.

`dig_tls::NodeCert::load_or_generate` persists the derived BLS/TLS leaf key **UNSEALED** at
`<cache_dir>/peer-net/identity/node.key`, because the dig-gossip pool listener loads it from disk
BY PATH (`dig_peer_protocol::load_ssl_cert`) and holds no key material of its own at that point.

Since `peer_id = SHA-256(TLS SPKI DER)`, possession of that one file IS possession of the node's
network identity for every purpose the network cares about — dialing as it, serving as it, and any
authorization keyed on it — **without touching either half of the sealed pair**. The
partial-exfiltration boundary §16.4 and §18.25 describe therefore holds for the SEED and does not
extend to the key peers authenticate.

- Any surface reporting the machine key's protection tier **MUST name this gap in the same
  sentence**, so a reader cannot take a copy-resistance claim about the seed as a claim about the
  node's network identity. The node satisfies this by appending a fixed caveat to every protection
  summary, in one place, so a later tier cannot be added without it.
- The node MUST NOT change `peer_id` in the course of closing this gap. A changed `peer_id`
  silently orphans every peer holding the old one, which is a worse outcome than the exposure.
- Sealing `node.key` is the preferred end state and MUST use the **same device key** as the seed.
  A separate device key would make the derived key unrecoverable after a device-key loss without
  also making the seed unrecoverable, and dig-keystore `SPEC.md` §17.5b establishes that
  `HardwareUnwrapFailed` cannot distinguish a copied blob from a wiped device — so an
  independently-sealed derived key turns a recoverable state into a bricked node identity.
- Until then the gap is DOCUMENTED, not implied. An honest stated gap is correctable; an unstated
  one is a shipped claim that is false about the artifact at risk.

### 18.25b. Master tier is authority that outlives the token (dig-node#255)

`dig-node-control-interface` states the rule as *"the effect outlives the token that invoked it"*.
That is necessary and not sufficient, and a node MUST apply the refined rule: a capability is
**master tier** when its effect both **outlives the token** AND **confers authority on a
principal** — installs someone the node will thereafter believe, obey, or speak to.

- `control.chiaPeers.add` / `.remove` — installs a peer believed WITHOUT corroboration. Master.
- `control.config.setUpstream` — persists a caller-chosen third party that every method this node
  does not implement is FORWARDED to, read on next start, and untouched by `pairing.revoke`.
  Master. The node ships with no upstream precisely so an unimplemented method answers a truthful
  local `-32601`; pointing it at an attacker-controlled URL makes that surface answerable by the
  attacker, and the escalation delegates — after the call the caller no longer needs the token.
- `control.cache.setCap`, `control.log.setLevel` — persist and survive revocation, but move a
  local resource budget or local verbosity. They name no principal and confer no authority.
  ORDINARY, deliberately: promoting them would break paired clients for nothing gained.

A node MUST resolve the tier by CALLING the contract's predicate, never by restating it as a string
match. Where the node enforces master tier AHEAD of the contract, the additional names MUST be a
single declared list that only ever WIDENS the contract's set, and a test MUST fail once the
contract adopts a name from it, so the two statements of one rule cannot drift.

**A persisted upstream MUST be a well-formed `http(s)` URL.** The node MUST reject a value with no
scheme it speaks, an empty host, whitespace in the host, or userinfo (`user@host` reads as one host
and resolves to another). Cleartext `http://` MUST be confined to loopback.

### 18.25c. Attacker-supplied text in an operator prompt (dig-node#346)

`pairing.request` is OPEN and unauthenticated, and the `client_name` it carries is composed into
the sentence an operator reads before granting a control token. It is therefore an input to a
privileged decision and MUST be treated as hostile.

- **The node MUST NOT silently truncate it.** An unmarked truncation is a forgery the node
  performs: padding with budget-consuming characters that render as nothing makes the node itself
  produce a short, trusted-looking name. The node MUST either REFUSE an over-long value at ingest —
  which is what `pairing.request` does — or mark the clip **IN-BAND**, as part of the rendered
  string, never as a separate flag a caller can drop.
- **The display budget MUST be charged on RENDERED WIDTH**, and Unicode `Cf` format characters,
  zero-width characters and bidi overrides MUST be neutralised — not merely `is_control()`. A
  neutralised character MUST render VISIBLY; deleting it lets an attacker choose what the operator
  sees just as effectively as inserting one.
- **Only the RENDERING is neutralised.** The stored `client_name` MUST stay byte-verbatim, because
  a value that is ever compared or used as an identity must not be quietly rewritten.
- **The value MUST NOT be able to add a line to the prompt**, which is line-oriented, and its slot
  MUST be quoted such that an embedded quote cannot terminate it and let the remainder read as the
  node's own words.

### 18.25d. A privilege-gated test MUST assert in every privilege branch (dig-node#355)

A security test that skips its assertions under `root` reports `ok` while proving nothing, and CI
containers commonly run as root — so the guard may never have executed. A silently-skipping test is
worse than a missing one, because it is counted as coverage.

Where a discriminator (a Unix mode bit) is genuinely not meaningful under `root`, the test MUST
assert the COMPLEMENTARY observable that still is — ownership, which only `root` can manipulate —
rather than skipping. Every branch must be able to fail.

## 18.26. Coin reservations — the two phases, and who owns the truth (dig_ecosystem#3127)

A **coin reservation** records that a coin is already committed to a spend that has not settled, so a
selector will not choose it again. It is BOOKKEEPING: it holds no key, signs nothing, and authorizes
nothing (§908). It narrows SELECTION only.

**The window it closes.** Between building a spend and that spend confirming, the chain still reports
its inputs as UNSPENT — the bundle is in a mempool, not a block. A second build in that window applies
the same selection rule to the same coins and picks the same one. The second bundle can never be
included, and it fails AFTER the money moved.

### 18.26.1. Authority — the node's set is authoritative

**Where a node is reachable, the NODE's reservation set is authoritative, and a client MUST defer to
it.** A client-local set is a fallback for the no-node case ONLY, and a client using one MUST NOT treat
it as covering another process.

This is stated rather than implied because the alternative is a rival implementation. A wallet key may
be in use by more than one process at once — dig-app holding the key, and a dig-node serving the same
wallet. **Two independent reservation tables over one wallet re-create exactly the double-select each
of them fixes locally**, and the two would disagree silently, which is worse than either being absent.

The node exposes its set over `control.wallet.reservations.held` / `.reserve` / `.release`.

### 18.26.2. Two phases of ONE lifecycle, not two systems

A coin may be held in either of two phases. They are stored separately because they are structurally
different, NOT because they are competing mechanisms:

| Phase | Table | Taken when | Ends when |
|---|---|---|---|
| **Lease** | `client_coin_reservations` | a client has SELECTED coins and is building a spend | it is released, its TTL lapses, or its coin is observed spent |
| **Broadcast** | `coin_reservations` | this node PUSHED a bundle | its parent `pending_transactions` row resolves (FK CASCADE) |

A `coin_reservations` row is a child of a `pending_transactions` row and therefore **cannot express a
hold taken before a bundle exists**, which is precisely what a client needs. The foreign key MUST NOT
be relaxed to accommodate one: its CASCADE is what retires a post-broadcast hold when its transaction
resolves. Nor may a lease be modelled as a synthetic `pending_transactions` row — that would make the
node report an in-flight spend that does not exist, a claim about money it cannot support.

**Both phases MUST be reported through ONE `held` answer under ONE `reservation_id` namespace.** A
caller asked whether it may spend a coin; both phases answer no, and it must not have to know which
phase a hold is in to get a correct answer.

**A selector MUST narrow against BOTH.** Narrowing against one reopens the window the other covers.

### 18.26.3. Acquisition

- **All-or-none.** `reserve` MUST take every named coin or none. Read-then-select-then-reserve is
  check-then-act, and two callers racing it both take the same coin. On a clash the node MUST have
  written NOTHING.
- **Atomicity is the WRITE-BEFORE-READ ordering**, not the `coin_id` PRIMARY KEY. The acquiring
  transaction MUST perform a write (retiring lapsed rows) BEFORE it reads, so every read happens under
  an exclusive write lock — the effect `BEGIN IMMEDIATE` would have. This is normative rather than an
  optimisation: a DEFERRED read-then-write transaction makes a losing racer collide while UPGRADING to
  a write lock, which surfaces as `SQLITE_BUSY` rather than a uniqueness violation, and would therefore
  be reported as an UNREADABLE SET rather than a clash — the wrong failure direction (§18.26.5),
  produced by contention alone.
- **An empty `coin_ids` MUST succeed**, yielding a handle that holds nothing. An empty selection can
  never conflict, so refusing it would make a legitimate no-op look malformed.
- **`reservation_id` is OPAQUE and unguessable** — 256 bits of OS randomness. A handle a caller can
  derive or guess lets it release a reservation it does not own, which is the double-select reached
  through the front door. Clients MUST NOT parse, derive or construct one.

### 18.26.4. Release — every ending, because the TTL alone is not enough

**A reservation with no release path is a wallet that locks itself out of its own funds, which is worse
than the double-select it prevents.** Four endings, all of which MUST work:

1. **Explicit release.** `release` frees a hold the moment its spend is known settled or known dead,
   rather than holding a person's coins for the rest of a window over a question already answered.
   Releasing a handle that names no live reservation MUST be a SUCCESS reporting nothing freed — a
   caller releasing on confirmation cannot know whether the TTL got there first, and an error there
   teaches callers to discard the result, which is how a release path stops being called. Release MUST
   free every coin of the handle or none.
2. **A confirmed spend.** A coin observed spent retires its hold with no release call, because the
   client that would have called it may be gone by the time the chain answers.
3. **The TTL.** Every hold MUST carry a finite lifetime whether or not anyone releases it.
4. **Process death.** The abandoned case is covered by (3) and by nothing else: nobody holds the
   handle, so only the unconditional expiry recovers the coin.

**Only a Lease is releasable on demand.** A post-broadcast hold is ended by the chain, not a caller:
the bundle may still be included, and freeing its inputs on request would invite a second spend of a
coin already committed.

**Expiry MUST NOT resurrect a spent coin.** The reservation set is a filter layered ON the chain read,
never a replacement for it.

**The applied lifetime, not the requested one, MUST be reported.** A node clamps a requested TTL to its
own maximum and applies its default when none is given; a caller told its own figure would wait on a
schedule the node does not keep. This node's default is **300 s** and its ceiling **600 s** — the
shorter figure being dig-account's default and the longer this node's own post-broadcast lifetime. The
two crates had disagreed harmlessly while they covered disjoint phases; the reconciliation makes the
shorter the DEFAULT and the longer the CEILING, under which neither is overruled.

### 18.26.5. Fail direction — REFUSE

**A node that cannot read its reservation set MUST refuse, and MUST NOT answer an empty set.**
"Nothing is reserved" and "I cannot tell you what is reserved" demand OPPOSITE actions: the first
permits a spend, the second must stop one. Collapsing them restores the double-select the set exists to
prevent. A guard that fails open is not a guard.

**A conflict MUST be distinct from a shortfall.** The user HAS the money; it is briefly committed and
returns when that spend settles or its hold lapses. Reporting insufficient funds sends a person to an
exchange to solve a five-minute wait. Over the control interface these are `-32044
WALLET_COINS_RESERVED` and `-32045 WALLET_RESERVATIONS_UNAVAILABLE` respectively.

**Where the two directions conflict, over-reserve.** An over-reserved coin costs a delayed spend; an
under-reserved one costs an invalid bundle built after the money moved.

### 18.26.6. Reservation narrows SELECTION, never BALANCE

A reserved coin is still the user's money and still counts toward what they hold. Balance and display
reads MUST keep counting it; only the spendable-set read is narrowed. Netting an in-flight send out of
the balance reports money as gone before the chain says so — the same class of lie in the opposite
direction.

## 19. Peer network — NAT traversal, discovery, address book, and content location

The standalone `dig-node` binary runs an L7 peer network (the in-process FFI/browser host does not —
§1, §15): a dig-gossip connected peer pool + relay reservation + introducer, a dig-dht content-location
index, node↔node PEX, and multi-source download — all over ONE mTLS identity
(`peer_id = SHA-256(TLS SPKI DER)`) on the dual-stack `[::]` listener (§4.1). This section is the
normative contract for how the node USES its P2P crates. All peer communication is IPv6-first with IPv4
as the fallback (§5.2 ecosystem HARD RULE).

### 19.1. NAT traversal — the full ladder (dig-nat)

Every outbound peer dial (DHT RPCs, multi-source range fetches, PEX candidate verification) MUST use the
FULL dig-nat traversal ladder, tried in canonical rank order:

> Direct → UPnP → NAT-PMP → PCP → hole-punch → Relayed

The relay tier (`Relayed`, via `relay.dig.net`) is the LAST resort — reached only after every direct +
port-mapping + hole-punch tier has failed. A node MUST NOT cap dials to `[Direct, Relayed]` (which skips
port-mapping + hole-punch and over-loads the relay). One shared config constructor
(`net::full_nat_config(per_method_timeout, stun_server)`, built from `dig_nat::NatConfig::default`) is
used at every dial site, so a new dig-nat tier is picked up everywhere at once. Each tier is bounded by a
per-method timeout so a dial never hangs.

### 19.2. STUN reflexive-address discovery

The node discovers its server-reflexive (public) transport address via STUN (RFC 5389) against the STUN
server co-located with the relay (`<relay-host>:3478`, derived from `DIG_RELAY_URL`). The STUN endpoints
are resolved across **both address families** (every A + AAAA record) and the Binding transaction is run
**IPv6-first with IPv4 fallback** (§5.2): the IPv6 STUN server is attempted first and IPv4 is used only
when the IPv6 server is absent/unreachable — the reflexive address is never nulled merely because IPv6
failed.

The reflexive query is run from a UDP socket bound to the node's **ACTUAL listen port** (the peer-RPC
port peers dial), not a throwaway ephemeral socket. The advertised candidate is therefore
`<reflexive-ip>:<listen-port>` — the reflexive public IP paired with the real listen port. The raw STUN
result's own port (the transient socket's NAT-mapping port) is deliberately DISCARDED: advertising it
would be undialable (a remote peer dialing an ephemeral binding reaches no listener). Pairing the
reflexive IP with the listen port yields the form a peer behind a different NAT can dial once the mapping
for that port is open (via UPnP/NAT-PMP/PCP or an endpoint-independent NAT).

The reflexive address is (a) configured on the NAT config so dig-nat's hole-punch tier can use it, and
(b) merged into the node's advertised DHT candidate set **IPv6-first** — a reflexive IPv6 address leads
the whole set; a reflexive IPv4 address leads the IPv4 fallback group — so a peer behind a different NAT
can dial or hole-punch to it. Discovery is best-effort + bounded; on failure the node advertises its
local addresses only. The wildcard bind address (`[::]`/`0.0.0.0`) is never advertised as a candidate.

The advertise path — candidate aggregation, family keying, de-duplication, and the IPv6-first family
ordering — is delegated to the canonical [`dig-ip`](https://crates.io/crates/dig-ip) crate (CLAUDE.md
§5.2, the ecosystem's single source of truth for the address-family / IPv6-first contract). Advertised
candidates are aggregated + source-tagged (`dig_ip::CandidateSource::StunReflexive` / `ListenAddr`) +
de-duplicated by `dig_ip::PeerCandidates`, then emitted in `dig_ip::Family` preference order (V6 before
V4); the node MUST NOT hand-roll a family sort in the advertise path. The DIAL path inherits the
local∩peer family intersection from dig-nat (which itself uses dig-ip), so the node does not duplicate
that intersection logic.

### 19.3. Content location — dig-dht is the sole locator

Content location ("which peers hold capsule X?") is the dig-dht provider index: the live locator is
`DhtProviderLocator → find_providers` inside the content engine (`NodeContent`). The
REDIRECT-ON-MISS / `dig.getAvailability` hint path uses this dig-dht locator EXCLUSIVELY (a redirect
must name genuine announced holders). The node keeps its own held-inventory provider records current
(announce / republish / refresh / gc) and withdraws them on shutdown.

**Download-side connected-pool fetch source (`PoolProviderLocator`, #1590).** The multi-source FETCH
path (`peer_serve_plaintext` → `NodeContent::fetch_resource`) uses a locator that UNIONS the dig-dht
locator with the node's currently-CONNECTED gossip-pool peers. This closes the #836 read-leg gap: on a
relayed / isolated network a holder is discovered in the DHT but its advertised provider record carries
addresses the reader cannot dial, so a DHT-only locate yields no REACHABLE source and the read
dead-ends at the §21 upstream backfill (404) even though the reader is ALREADY CONNECTED to that holder.
Offering every connected pool peer as a fetch candidate lets the download reach the holder over the
established connection. A pool peer's candidate MUST list its addresses newest-session-first: dig-gossip
republishes `PoolEvent::PeerAdded` when a freshly authenticated session SUPERSEDES a stale slot for the
same `peer_id` (newest-wins re-adoption), and that is typically a MOVE — a dead relay circuit replaced by
a direct dial. The superseded addresses are RETAINED as trailing fallbacks (a still-working older path is
not discarded) but MUST NOT be dialed first. Re-adoption MUST NOT grow the candidate set: the pool is
keyed by `peer_id`, so a republished `PeerAdded` upserts one entry — a re-adopted peer is one candidate,
never two.

A `PoolEvent::PeerRemoved` carries WHY the peer left, and the node MUST preserve the distinction between a
peer that FAILED and one that merely departed. `Banned` is the only reason that is behavioural — it makes
the peer ineligible until re-added (§9.4). `Displaced` names a peer that was HEALTHY and was cycled out to
make room for a holder content discovery found outside the persistent set; it is the one reason that is not
a failure, and the node MUST NOT record it as evidence against the peer. Specifically it MUST NOT be mapped
to `Banned` (which would make the node's own capacity decision bias selection toward unremembered peers — a
sybil) nor to `Dead` (which asserts a keepalive found the peer unresponsive, a claim a displacement is no
evidence for). A reason the selector has no variant for MUST fold to `Disconnected`, the reason that carries
no such claim.

A connected-pool holder whose `dig.getAvailability` confirm probe CANNOT BE OBTAINED is admitted to
the download anyway (`PoolConfirmTransport`, #836): dig-download's `locate_and_confirm` DROPS any
provider whose availability answer is not *available*, and a connected holder's probe can transiently
FAIL on a relayed / isolated net — which would drop the connected holder, issue ZERO `dig.fetchRange`,
and dead-end the read at the §21 upstream backfill (404) despite a connected, serving holder. On a probe
ERROR the live connection stands as the confirmation and the fetch proceeds straight to
`dig.fetchRange`. Safety is preserved by the whole-resource merkle check, which binds every served byte
to the chain-anchored root: a connected NON-holder simply fails its ranges and is dropped there.

**The bypass covers a MISSING answer and MUST NOT cover a NEGATIVE one.** A connected peer MUST still be
ASKED, and an answer of *not-available* MUST be honoured exactly as a DHT-only provider's is. Fabricating
*available* for every connected peer — the pre-0.153.0 behaviour — did not merely add a bad candidate: it
qualified a peer for free while the DHT-only true holder still had to earn its place, so a STALE record
OUTRANKED the real holder (dig_ecosystem#3159 measured 21 range attempts at a stale `peer_id` and 0 at
the holder). Honouring a not-available answer is sound under NC-12 because it is a self-NEGATIVE claim
and can never admit a byte; the worst case is skipping a peer that lied about not holding, which costs
one candidate. Trusting a self-POSITIVE claim is what NC-12 forbids. A DHT-only (non-pool) provider still goes through the real
`dig.getAvailability` confirm. This source is DOWNLOAD-only — it never feeds the redirect/availability
hint above.

**The availability answer MUST agree with what the node can SERVE (#1592).** `dig.getAvailability` is
the gate every DHT-discovered holder must pass — dig-download's `locate_and_confirm` DROPS a provider
whose answer is not *available* BEFORE any `dig.fetchRange` — so at ROOT / RESOURCE granularity the
answer is DERIVED FROM THE SERVABLE SOURCE: the existence of the very capsule module
(`<cache>/modules/<store>/<root>.dig`) the serve path reads. It MUST NOT be derived from an
inventory snapshot that can lag a write, and any cache retained for cost MUST be invalidated on every
inventory-changing write (pin, §21 sync, on-demand fetch-and-cache, gap-fill, backfill, eviction).
A snapshot lags in BOTH damaging directions: a capsule that landed after the snapshot was taken (a
gap-fill / §21 sync / fetch-through / pin write concurrent with the peer-facing inventory walk) is
already servable, and answering *not available* for it drops a holder that would have served the bytes
— the DHT-only discover→read leg's false negative; conversely a snapshot that lags an EVICTION would
claim availability the node cannot serve. Consequently: a capsule gained at runtime is IMMEDIATELY
reported available, an evicted one IMMEDIATELY is not, and a capsule genuinely not held is still
reported not available (the answer is never weakened to an unconditional *available* — the merkle
verify remains the integrity gate downstream, but availability MUST NOT lie in either direction).
STORE granularity (`root` absent) still enumerates the held `roots` from the inventory walk, which a
single-path existence check cannot answer; that `roots` list is ordered CANONICALLY (by root hex),
NEVER by an access-time/recency field, so the permissionless peer surface leaks no read-recency
ranking of the operator's interests. Because this method is peer-reachable (§7.4), the
per-request cost is bounded: one path existence check per queried item, and the whole-cache directory
walk is performed AT MOST once per batch and ONLY when some item asks at store granularity. Every
caller-supplied `store_id`/`root` is validated canonical 64-hex before any path is built from it (the
same path-traversal guard `cache.removeCached` applies), so a crafted key answers *not available*
without touching the filesystem.

A `dig.fetchRange` answer is a stream of `u32`-BE length-prefixed JSON frames, each frame's `bytes`
field the **base64** encoding of that window's ciphertext (the canonical
`dig_rpc_protocol::types::RangeFrame` wire this node's serve path emits). A reader MUST base64-decode
it; reading the field as raw bytes yields the base64 TEXT and every frame is rejected as
over-length — the #1586 read-leg blocker, which required dig-nat >= 0.11.2 to fix.

**Per-range verification metadata — EVERY frame, not just the first.** A served frame MUST carry the
metadata that makes it independently checkable against the chain-anchored generation root:
`total_length`, `root`, `chunk_count`, and — when the window begins exactly on a chunk boundary —
`first_chunk_index` (with `chunk_index` as its pre-existing alias for the same value). `chunk_lens` and
`inclusion_proof` are the resource-scaling PROLOGUE and ride the stream once rather than every frame
(see the framing rules below). A downloading peer fetches ranges in parallel from many holders, so a frame that
declared no `root` (as only-the-first-frame metadata left every later range doing) could not be checked
for generation consistency on arrival: a wrong-generation source was detectable only after the whole
resource had been paid for in bandwidth. A frame whose window starts MID-chunk MUST omit
`first_chunk_index`/`chunk_index` entirely rather than assert an index the caller's own alignment check
would contradict.

The served window is EXACTLY the requested span, never widened to a chunk boundary: a verifying client
fails a range closed on any length but the one it planned.

**A `dig.fetchRange` STREAM MUST NOT serve past the requested `[offset, offset+length)` span, however
far the resource itself continues (#1619).** The per-frame window cap above bounds one FRAME; a holder
answering a request whose span exceeds one node window still streams MULTIPLE frames (advancing
`offset`) to cover it, and that multi-frame loop MUST stop the instant the requested span is satisfied
— NOT merely when the frame's own `complete` flag reports the resource exhausted. `complete: false` on
the LAST frame of a satisfied request is normal and expected: it means the RESOURCE continues past the
request, not that more of the STREAM is still to come. A holder that keeps streaming past the requested
`length` turns a client's small probe range (e.g. `{offset:0, length:1}` — dig-download's own
metadata-probe pattern, sent on every download) into an unbounded amplification: hundreds of bytes in
for the WHOLE resource's verification-metadata-laden frames out. The client-side clip
(dig-download's own defensive re-clamp of an over-length frame) is defense in depth, never a substitute
for the holder's own bound — re-introducing a client-side REJECTION of an over-long frame is the #836
class of defect (a false negative that makes an honest holder look like a liar) and MUST NOT return.

**A FRAME is bounded by `MAX_RANGE_FRAME_PAYLOAD`, not by the request window.** A serving node MUST
split a requested span into frames carrying at most `dig_nat::MAX_RANGE_FRAME_PAYLOAD` (32,768) raw
payload bytes each, and MUST write each frame through `dig_nat::RangeFrame::encode`. `RANGE_WINDOW`
(3 MiB) is the default and maximum a single REQUEST may ask for; it is NOT a valid per-frame size. The
two are 96x apart, and `bytes` travels base64, so a frame sized by the request window produces a body
past `dig_nat::MAX_FRAMED_BODY` (65,536) which a conforming receiver is REQUIRED to reject — making
every resource over roughly 48 KiB unserveable by any holder (dig_ecosystem#1640/#1668). The same
ceiling binds `dig.fetchModuleRange`, whose frames the puller also decodes with `dig_nat::RangeFrame`.

Frames MUST be produced through the dig-nat type rather than hand-built as JSON and written with an
uncapped framer. The encoder's refusal is what makes an unserveable frame impossible to emit rather
than merely unlikely: a sender that builds its own JSON has no way to learn it produced something the
receiver must reject, so the divergence can only surface as a failed read in production.

**Which metadata rides which frame.** The metadata splits by whether it scales with the RESOURCE
(dig-nat `SPEC.md` §5.1.1 is normative):

- The **identity set** — `root`, `total_length`, `chunk_count`, plus `chunk_index`/`first_chunk_index`
  where the window is chunk-aligned — is fixed-size and MUST ride EVERY frame. It is what lets a reader
  reject a wrong-generation or wrong-layout holder the moment a frame arrives.
- The **prologue** — `chunk_lens` and `inclusion_proof` — scales with the resource and MUST be sent
  once per range stream, never repeated on later frames. A layout exceeding
  `dig_nat::MAX_CHUNK_LENS_PER_FRAME` (2,048) entries MUST be sent as a **paged prologue**: successive
  frames each carrying at most that many entries, each stamped with the `chunk_lens_offset` at which its
  page begins. Pages MUST tile the array exactly — no page may be empty, and every page except the tail
  MUST be exactly `MAX_CHUNK_LENS_PER_FRAME` entries, since a short non-tail page leaves a gap no
  page-aligned page can ever fill.
- A stream MUST NOT report `complete` while prologue pages are still owed, and MUST NOT end before the
  prologue is delivered whole — including when the requested span needs FEWER frames than the prologue
  does, in which case the remaining pages ride zero-payload frames. `chunk_lens` is a DECRYPT input
  whose entries must sum to `total_length`, so a reader MUST discard a partial layout entirely: a
  layout short even one entry cannot decrypt the resource, making it unusable rather than partially
  useful.
- A request MAY set `skip_layout` when the client already holds the commitment for this `root`; a
  holder honouring it omits the resource-scaling set and ONLY that. The identity set is never
  suppressed, because it is what detects a wrong-generation holder on arrival. `skip_layout` absent or
  false preserves the earlier behaviour, so a holder that does not understand the field is never broken
  by it.

Every frame's declared `length` MUST equal its own payload length. A frame whose `length` disagrees
with its `bytes` is one a reader distrusts, and no receiver in this tree validates the relation, so the
obligation is the sender's alone.

**`dig.fetchModuleRange` frames** obey the same framing ceiling, and carry `total_length` — the served
window's length — on EVERY frame rather than only the first. They carry no `root` or `chunk_count`: a
`.dig` capsule is self-verifying against the chain anchor on install (§the module-anchor gate), and this
leg has no per-resource chunk layout to count, so a `chunk_count` here would be a claim about a structure
that is not present.

**KNOWN CONSTRAINT — the paged prologue has no RECEIVER in this dependency tree.** dig-download 0.11
reads `chunk_lens` from the first frame only and ignores `chunk_lens_offset` and every later page
(`ChunkLensAssembler` ships in dig-nat 0.14 / dig-download 0.12; this node is held at 0.13 / 0.11 by
dig-gossip and dig-peer-selector — see `crates/dig-node-core/Cargo.toml`). So a resource whose layout
exceeds `MAX_CHUNK_LENS_PER_FRAME` — roughly **128 MiB** at the 64 KiB chunk target — is served
correctly by this node but still fails at the reader, now at its `chunk_lens`-sum check rather than at
frame decode. This is FAIL-CLOSED and cannot mis-verify: a partial layout is refused, never used. It is
resolved by the same cascade as the rest of the 0.14 move (dig_ecosystem#1686).

`chunk_count`, `chunk_lens_offset` and `skip_layout` are additive wire fields (§5.1 backwards
compatibility): an older reader ignores them, and a newer reader parses an older frame with each absent.

A serve MUST NOT emit a per-CHUNK inclusion proof (`range_proof`). No such proof is derivable from the
store format: the generation root's merkle leaves are per-RESOURCE (`resource_leaf(ciphertext)` =
SHA-256 of a resource's WHOLE ciphertext, folded by `MerkleTree::from_leaves`), so a single chunk has no
committed digest to prove and recomputing the leaf requires every other chunk's bytes. The
chain-anchored binding is therefore established once, over the assembled resource, via
`inclusion_proof`; a per-chunk proof would be unverifiable decoration inviting a client to trust bytes it
cannot check, and is REFUSED rather than fabricated. Real per-chunk proofs require a store-format
prerequisite: a per-resource chunk-commitment structure added as a NEW leaf-kind / data-section id with
version dispatch (or carried as a parallel commitment alongside today's leaf) — NEVER a redefinition of
`resource_leaf` itself, since `dig-client-wasm`/`dig-capsule-wasm` check that value byte-identically and
`PublicManifest.sha256_latest` is normatively pinned to it (digs `SPEC.md` §8), so existing capsules keep
reading unchanged. Out of scope until that prerequisite exists (dig_ecosystem#1601).

The download locator (dig-dht ∪ connected pool) is itself SELF-EXCLUDED: THIS node's own `peer_id`
(hex) is dropped from the fetch-candidate set before any dial, exactly as the DISCOVERY leg is (#1584).
A relay-introduced self-connection can surface this node in its own gossip pool (`peer_id == local`);
offered as a fetch candidate it would self-dial (Direct → own IP → connection refused; Relayed →
refused self-dial), starving the download's confirm round and dead-ending the read at HTTP 404 despite a
reachable holder being connected. Two defenses hold this: a self `PeerAdded` is dropped at the pool feed
(`on_pool_event`) so self never enters the connected pool OR the selector registry, and the whole
download locator is wrapped so NO source — DHT or pool — can ever offer self on the fetch/dial path
(#836/#92, run e2e-836-arb-20260725-084501).

**Announce vs. locate granularity (resource→capsule fallback).** Inventory is announced at STORE and
CAPSULE (`store_id:root`) granularity ONLY; per-RESOURCE provider records are deliberately NOT announced
(a capsule holder serves every resource inside it, so per-resource records would be redundant and would
explode DHT write volume). A `/s` resource read miss, however, locates by a RESOURCE content id. The
node's locator therefore MUST bridge the two: on a `ContentId::Resource` lookup it ALSO queries the
parent `ContentId::capsule(store_id, root)` and unions the holders (deduped by `peer_id`, resource-key
hits first), so Tier-2 peer fetch resolves the announced capsule holder and proceeds to
`dig.getAvailability` + `dig.fetchRange` for the specific resource. Without this bridge a resource read
finds no providers and dead-ends at the public-RPC tier even when a holder is discoverable
(`CapsuleFallbackLocator`, #1580).

**Announce-on-inventory-gain (the reshare / flywheel invariant).** A node that GAINS a capsule at runtime
— by ANY path: a hosted pin, a §21 whole-store sync, a chain-watch gap-fill, or the read-side
backfill-cache (a reader that caches what it just fetched) — MUST re-announce its DHT inventory so peers
immediately discover it as a NEW holder of that capsule (§14.1). This is the discoverability half of the
content-replication flywheel (#1423/#1425): every read makes content more available because the reader,
on caching, becomes a discoverable holder. The re-announce is fired ONCE per freshly-landed capsule at the
single centralized landing site (`CapsuleStore::cache_fetch_and_cache`, through which every runtime
capsule-gain path flows), guarded so an already-held capsule is a no-op (unchanged inventory → no
re-announce). It is best-effort and a no-op on the in-process FFI path (no peer network / inventory
refresher installed).

**Retract-on-inventory-loss (dig-sex SPEC §7.1).** The converse binds equally: a node that LOSES a
capsule MUST re-advertise, so it stops naming itself a holder of content it has deleted. A node that
evicts without retracting spends every reader's dial budget on a guaranteed miss, and does so
invisibly — the advertiser observes nothing wrong, and only the dialler pays.

- The size-cap sweep (`Node::evict_modules_if_needed`) MUST report the capsules it ACTUALLY deleted,
  and MUST drive a reconcile from that list. A capsule the policy nominated but whose delete FAILED is
  still held and MUST still be advertised.
- The delta is computed by `dig_sex::holdings` — `after_eviction` for a sweep, `after_admission` for a
  land that sacrificed capsules to make room — and the node performs only the I/O. A delta that changes
  nothing MUST NOT cost a reconcile, which is a Kademlia round trip per changed id.
- **Ordering is normative.** On a land that evicts, the sweep MUST run BEFORE the advertisement, so the
  one reconcile covers both the arrival and its cost. Advertising first and deleting after leaves the
  node advertising the victim until some unrelated inventory change happens to reconcile it, which on
  a quiet node is never.

### 19.3a. Real-time holdings announce — dig-gossip opcode 222 (#1429)

Beside the DURABLE provider records above, the node maintains a REAL-TIME holder signal. The durable
records converge only as fast as the last PUT reached and a departed holder lingers for its record's TTL;
the announce closes that gap.

**Egress (MUST).** Every inventory reconcile MUST derive both effects from ONE delta: the DHT records
(announce gained ids, ACTIVELY retract lost ids via `retract_own_provider`, never the passive
`withdraw_provider` — a passively withdrawn record keeps answering `find_providers` with this node for
content it can no longer serve, costing each reader a wasted dial), AND a signed opcode-222
`HoldingsAnnounce` carrying `Add`/`Remove` deltas for exactly those ids. A reconcile larger than
`HOLDINGS_MAX_CHANGES` (256) deltas MUST be SPLIT across frames, never truncated — truncation would drop
retracts and leave this node advertising content it does not hold.

- The announcement MUST be signed by the node's own `NodeCert` leaf (ECDSA-P256), because the wire
  derives `provider_peer_id` from `SHA-256(provider_spki)`; signing with any other key announces an
  identity no peer can dial.
- The advertised addresses MUST be the SAME advertised candidate set the DHT provider records carry.
- `seq` MUST strictly increase per node, and MUST NOT restart from zero — a node resuming from zero has
  every announcement dropped as a replay by peers that remember its previous watermark. The
  implementation seeds from the wall clock and increments once per batch. Note the two limits of that
  seed, neither of which a receiver can be harmed by: it does NOT guarantee the seed exceeds every value
  previously announced (a node averaging more than one batch per second outruns its own clock, so the
  seed after a restart can be below the counter it reached), and a backwards clock adjustment has the
  same effect. The consequence is self-inflicted silence — this node's announcements are ignored until
  the counter it left behind is passed — never an accepted replay. Seeding above the last value
  announced requires persisting the counter, which is deferred (#1477).
- A degraded node (no signable leaf, no inbound receiver) MUST remain discoverable through the durable
  DHT records — the real-time layer is additive and MUST NOT be a hard dependency of discoverability.

**Peer-presence re-announce (MUST, #1734).** A node MUST re-announce its CURRENT holdings in full — every
held content id as an `Add`, with no diff — whenever its connected peer pool rises from ZERO peers to one
or more, including the first such observation after bring-up. It MUST NOT re-announce merely because an
already-peered pool grew.

A re-announce MUST be broadcast on the LOCALLY-ORIGINATED path (`GossipHandle::broadcast_local`),
never the forwarding one. The announcement for an unchanged inventory is byte-identical to its
predecessor, so the seen-set deduplication that correctly suppresses a relayed message loop also
suppressed every repeat of this node's OWN announcement for the life of the process — which made the
MUST above unimplementable in practice, since the startup announce at zero peers poisoned the entry and
no later re-announce reached the wire (dig_ecosystem#3061). The hash is still RECORDED, so the same
announcement arriving back from a peer and offered to the forwarding path is still dropped: the
exemption is one-directional, and a RECEIVED message MUST NOT be relayed on the local path, which would
turn one echo into a broadcast storm.

The reconcile delta above is computed against this node's OWN local provider records, so it answers "what
changed here", never "what do my peers know". Those two diverge silently as soon as an inventory change
happens with nobody connected: the local records move, the flood reaches zero peers, and every later
reconcile of the same inventory is a no-op. Without this rule a node that pinned before its first peer — or
that RESTARTED with content already cached, where the remembered inventory is seeded from disk before any
peer connects — holds the content, has recorded it as announced, and is invisible to every peer it later
connects to, with a restart re-entering the same state. Re-stating the whole inventory is safe because an
`Add` is idempotent at every receiver under an advancing `seq`.

**Ingress (MUST).** An inbound announcement is applied ONLY after all of the following, fail-closed, at a
single chokepoint. dig-dht is crypto-free by design, and `ingest_verified_provider` is the sole sanctioned
bypass of its mTLS self-announce check, so these are the whole of the authentication:

0. **DECODE refuses a frame whose declared counts exceed the protocol maxima, BEFORE reserving for them**
   (#1723). The wire states its batch size and each `Add`'s address count as `u16`, so both are the
   sender's to choose; decode MUST check them against `HOLDINGS_MAX_CHANGES` (256) and
   `MAX_ADDRS_PER_CHANGE` (32) before any allocation is sized from them. This gate is stated separately
   from gate 1 because it necessarily runs BEFORE it: decode precedes the signature check, so an
   allocation sized here is one an UNAUTHENTICATED peer commissioned. A ~200-byte frame declaring
   65,535 addresses would otherwise reserve ~2 MiB, and no later gate can refund it. The general rule
   this instantiates: **never size an allocation from a number a peer supplied.**
1. `verify_holdings_announce` passes (batch cap, `SHA-256(provider_spki) == provider_peer_id`, P-256 SPKI,
   valid signature over the `dig:holdings:v1` domain-separated message).
2. `provider_peer_id` is CANONICALIZED (decoded to 32 bytes, re-encoded lowercase) and every subsequent
   comparison, map key and provider argument uses ONLY that value. This is normative, not hygiene: hex
   decoding is case-insensitive and the signature covers the DECODED bytes, so one identity has many
   spellings that all verify. A receiver that keys on the raw wire text gives each spelling its own replay
   watermark and misses a lowercase self-identity comparison, turning gates 3 and 5 into no-ops at zero
   cryptographic cost. A `provider_peer_id` that is not 64 hex characters MUST be refused before it is
   compared, keyed, or logged.
3. The announcement is NOT attributed to this node's own (canonicalized) `peer_id` — the network MUST NOT
   be able to tell a node what it holds.
4. `announced_at` is within **±300 s** of the receiver's clock; otherwise the announcement is refused as
   stale. REQUIRED, not defence in depth: a `Remove` delta carries no expiry of its own, so without this
   the only barrier to replaying a captured retract indefinitely is the in-memory watermark of gate 5 —
   which a restart clears and a capacity eviction drops, letting anyone de-list an honest holder by
   replaying that holder's own old retract at a freshly started peer. The signature binds WHO announced;
   only this bound binds WHEN. The check is symmetric, because a future-dated frame stays replayable
   longer than it should.
5. `seq` strictly advances beyond the highest already applied for that CANONICAL provider identity;
   otherwise the announcement is dropped (a replayed older frame MUST NOT resurrect a retracted record).
   A provider not yet seen has NO watermark, which is distinct from a watermark of zero — `seq` is not
   required to start at 1. A rate window elapsing MUST NOT reset the watermark: replay protection is not
   a rate limit.
6. Two token buckets, both within a 60-second window: at most **10 announcements per PROVIDER**, and at
   most **1,024 (`4 × HOLDINGS_MAX_CHANGES`) deltas per TRANSPORT SENDER**. They are keyed differently on
   purpose — a provider id is attacker-minted so its bucket map must be capacity-bounded and is therefore
   evictable, whereas the sender key space is the connected pool and cannot be inflated from off-network,
   making it the unbypassable backstop. A REJECTED announcement MUST charge neither bucket, or the
   limiter itself becomes the denial of service.

**Bounded state (MUST).** A rejected announcement MUST NOT allocate tracking state. Admission is decided
in full BEFORE any per-provider or per-sender entry is created, because every rejection path returns early
and would otherwise skip the eviction step, letting an attacker-minted key space grow the maps for the
price of one ~180-byte frame per entry. Admitted entries are capacity-bounded (1,024 senders, 8,192
providers) with least-recently-seen eviction.

**Untrusted fields (MUST).** `provider_peer_id` is a `u16`-length-prefixed wire string and may carry tens
of kilobytes of arbitrary UTF-8, including newlines and terminal escapes. No peer-supplied field may be
emitted to the log; only the canonicalized identity may be. Bounding log LEVEL bounds volume, not content.
An `Add` delta's address list MUST be truncated to `MAX_ADDRESSES_PER_RECORD` before it is mapped, since
its length is an attacker-declared `u16`.

**Operator control (SHOULD).** `DIG_HOLDINGS_INGEST=0` disables the ingress while leaving egress intact;
discovery then degrades to the durable DHT records rather than failing.

**Attribution (MUST).** The provider identity used for both `ingest_verified_provider` and
`remove_provider_record` MUST be the VERIFIED signer and nothing else. A retract therefore removes only
the signer's own record and can never de-list another holder of the same content key. The wire carries no
per-delta peer field, so this holds structurally: the receive path accepts no caller-supplied provider id.

**No amplification (MUST).** The ingress performs NO egress — it never re-broadcasts, dials, probes or
fetches. One inbound announcement costs the receiver bounded local map work only, so a cheap anonymous
message can never make honest peers do more work than the sender did.

**Reach is ONE HOP (normative, and deliberate).** An announcement is delivered to the announcer's directly
connected peers and is NOT re-flooded onward: dig-gossip's Plumtree eager/lazy dissemination applies to
frames a node ORIGINATES via `broadcast`, and the opcode-222 receive path does not re-broadcast. The
real-time layer is therefore a NEIGHBOURHOOD freshness signal, and the DHT provider records (PUT to the
k-closest peers and republished) remain the only network-wide discovery mechanism. This is sufficient for
the layer's purpose:

- For an ADD, one hop covers the highest-value case. A node's direct peers are exactly who is positioned
  to fetch from it, and the fetch path already prefers connected-pool holders over a DHT record. Peers
  further away discover the new holder through the durable records, as they always did.
- For a REMOVE, one hop leaves peers more than one hop away holding a stale record until TTL. That is a
  LATENCY gap, not a correctness gap: the local record is deleted at once by `retract_own_provider`, the
  k-closest copies age out, and the cost of a stale record is one failed dial that the peer-selector
  deranks.

Re-flooding verified announcements would close the remaining gap but MUST NOT be added at the ingress:
that would make one inbound message produce N outbound, which is precisely the amplification this layer is
built to avoid. The correct shape, if wider reach is later required, is for dig-gossip to relay verified
opcode-222 frames through its EXISTING Plumtree seen-set (which already provides dedup and flood control),
never a re-broadcast from the receive path.

**False claims.** A peer MAY announce content it does not hold. This is bounded by cost asymmetry rather
than prevented: the liar pays a signature and a flood, and buys at most one failed dial or a
`dig.getAvailability` answering "no", after which the peer-selector deranks it. No merkle- or
chain-verification decision ever rests on an announcement.

### 19.4. Address book — durable, IPv6-first, provenance + TTL

The node maintains a durable peer address book: every learned peer candidate — from PEX, `dig.getPeers`,
the relay introducer, or an observed pool peer — is INGESTED into the book (keyed by `peer_id`) rather
than dialed-and-dropped. The book:

- unions each peer's directly-dialable addresses, ordered **IPv6-first**;
- records provenance (a first-hand pool / `getPeers` sighting is not downgraded by a later PEX hint) and
  a freshen timestamp;
- persists relay-only / not-currently-dialable hints (they survive to seed a later dial);
- reads back a ranked, non-stale candidate list (IPv6-dialable peers first, then other dialable, then
  relay-only; ties by recency), evicting the stalest entry at a capacity bound and dropping entries past
  a staleness TTL.

### 19.5. PEX candidate handling

PEX-discovered candidates are HINTS (proven only by a successful mTLS dial). On receiving a PEX candidate
batch the node offers EVERY candidate (including relay-only) to the address book (§19.4), then dials a
bounded number selected from the book — verifying each over the full ladder (§19.1) and adopting the
verified connection into the pool. A failed dial keeps the hint in the book for a later retry; a peer
already in the pool is skipped.

### 19.6. Selector-driven dial ordering

The shared self-optimizing peer selector (dig-peer-selector) that ranks download SOURCES also orders
which address-book candidates the node DIALS first: dials are ranked by the selector's content-agnostic
per-peer quality (reliability blended with throughput; a banned peer sinks to the bottom; a cold peer is
explored at a neutral rank). The node reuses the ONE selector instance; IPv6-first order is preserved
among equally-ranked peers. In PRIVACY mode the selector does not apply (the onion path uses its own).

### 19.7. Crate-API integration status (release-first follow-ups)

Two intended crate-side integrations are pending a release-first dig-gossip change and are realized
node-side in the interim:

- dig-gossip exposes no PUBLIC production API to ingest external addresses into its `AddressManager`
  (only a hidden test hook), so the durable address book (§19.4) lives in the node; when dig-gossip ships
  a public `offer_addresses` ingest API the book flushes into the crate `AddressManager` (one source of
  truth).
- dig-gossip's `PeerPoolConfig` exposes no dial-priority hook, so selector-driven ordering (§19.6)
  applies to the node's PEX candidate dials; when dig-gossip ships a pool dial-priority hook the same
  ranking drives the pool's own maintenance dial loop.

Exercising the connected pool end-to-end is gated on the network-genesis bring-up (the pre-launch
placeholder genesis is rejected by `GossipService::start`); these behaviors are unit-tested
independently of a live pool.

### 19.8. Relay reservation — control dial + advertised listen candidates

The node holds ONE persistent relay reservation (dig-nat `run_relay_connection`) sharing a single
`Arc<RelayStatus>` with the gossip pool. The reservation advertises the node's real gossip listen
candidates in the RLY-001 `Register` message (`listen_addrs`, dig-nat 0.3.0's `Register.listen_addrs`
field): the node offers its `gossip_port` on the IPv6 unspecified address FIRST, then the IPv4
unspecified address (§5.2 IPv6-first). The relay performs reflexive-IP substitution — it pairs the
advertised PORT with the source IP it observes — so a peer behind a different NAT receives a DIALABLE
`<reflexive-ip>:<gossip-port>` candidate. dig-nat 0.3.0 is adopted now that dig-dht, dig-download, and
dig-peer-selector are republished accepting dig-nat `>=0.2,<0.4`, so the graph unifies at exactly one
dig-nat 0.3.0.

The node retains the live `GossipHandle` for the pool so the CONTROL surface can act on it:
`control.peers.connect` dials a discovered/known peer into the connected pool, `control.peers.disconnect`
drops a pooled peer, and `control.peerStatus` enumerates the pool as the per-peer array (§8.7). The
in-process FFI host runs no peer network, so it retains no handle — connect/disconnect report "no peer
network" and the peer array is omitted.

## 20. Logging — structured JSONL file + human stderr (#553)

The node adopts the shared `dig-logging` building block (`dig-logging` crate, `dig_ecosystem` #547),
so its sink layout, JSONL schema, log directory, rotation, level control, correlation ids, redaction,
and `logs` verbs are byte-identical to every other DIG service binary. `dig-logging`'s own `SPEC.md`
is the normative contract for those; this section records what dig-node MUST do.

### 20.1. Where the subscriber is installed

The node MUST install the `dig-logging` subscriber exactly once, at a SERVE entrypoint, and hold the
returned guard for the process lifetime:

- the foreground `run` path and the unix daemon (`serve` via the CLI entrypoint) install it as run
  context `service` when the process is an installed OS-service run, else `cli`;
- the Windows service body (`run-service`, §9.4) installs it as run context `service` immediately
  after marking the process a service, BEFORE building the runtime — a Windows service has no
  console, so the JSONL file is the only log.

A one-shot CLI command (`status`, `pair`, `config`, …) does NOT install the subscriber: it neither
needs a rolling log file nor the maintenance thread. Installation is best-effort — a logging failure
(subscriber already set) is reported on stderr and MUST NOT stop the node serving.

An UNWRITABLE log directory MUST NOT cost the console sink. `dig-logging` 0.2.0 degrades to
console-only logging and reports the reason via `LogGuard::file_error()`; the node MUST keep serving
and MUST report that condition on `control.status` (`logging.file_logging: false` plus
`logging.file_error`).

`logging.file_logging` is a START-UP verdict, not a live one. `dig-logging` 0.2.0 determines file-sink
health ONCE, while installing the subscriber, and exposes no way to revise it afterwards, so
`control.status` MUST report it as of logger initialization: `logging.file_logging: true` asserts only
that the rolling JSONL sink OPENED SUCCESSFULLY at start-up, and `logging.file_error` names the reason
it did not. A sink failure that occurs AFTER initialization — the log directory deleted, the volume
filled, a rotation failure — is NOT detected, and the node MUST NOT be read as claiming otherwise.
Live file-sink health becomes reportable only once `dig-logging` can revise `file_error` after init.

The log directory follows `dig-logging` SPEC §3: the machine root `<…>/DigNetwork/logs/dig-node`
(`C:\ProgramData\DigNetwork\logs\dig-node`, `/Library/Logs/DigNetwork/dig-node`,
`/var/log/dig/dig-node`) for a service run, the per-user dev-fallback for an unprivileged `dig-node
run`, and `DIG_LOG_DIR` overrides both — mirroring the #501 daemon/CLI state-dir split.

### 20.2. Levels — used by MEANING

Events are emitted at the level that matches their operational meaning, not uniformly: `error!`
(operation failed / broken invariant), `warn!` (recoverable, degraded, or a fallback taken — a
listener that failed to bind non-fatally, a TLS/plaintext downgrade, a control-token persist
falling back to an in-memory token), `info!` (sparse operator lifecycle — the node listening with
its bound addresses + upstream, a listener up, leaf renewed, shutting down), `debug!` (developer
diagnosis — per-request RPC dispatch, a per-tick self-heal pass, a config-disabled surface),
`trace!` (firehose). The default filter is `dig-logging`'s noise-trimmed `info`.

### 20.2a. Peer-facing serves MUST announce their outcome

Every inbound peer-facing serve MUST record its OUTCOME in the log, so a read can be diagnosed from
logs alone and never requires a packet capture. Concretely:

- An inbound `dig.fetchRange` MUST emit one `info!` line per request naming the requesting `peer_id`,
  the content id (`store_id`, `root`, `retrieval_key`), the requested `offset`, and the outcome — one of
  `served` (with the total `served_bytes`, the `frames` those bytes were split into, and whether a proof
  was attached), `not-held`, `bad-range`, or `redirect` (each with the catalogued error code the caller
  was given and a short reason). The reported `offset` is always the offset the caller REQUESTED, never
  how far a partial stream advanced. Per-frame detail (offset, byte count, chunk index, chunk alignment)
  is `debug!`, and a frame whose window does not start on a chunk boundary OMITS `first_chunk_index`
  rather than reporting `0` — the same omit-what-cannot-be-stated-truthfully rule the frame metadata
  itself follows (§19.3, *Per-range verification metadata*).
- `served` means bytes were streamed. A serve path that answers an unsatisfiable range with an error
  frame (the fetch-through miss path, §19.3) MUST report that refusal, NOT `served` with a zero byte count,
  and `frames` MUST be the frame count actually written. An outcome line that says `served` for a
  request that served nothing reintroduces the exact ambiguity this section removes.
- An inbound `dig.getAvailability` MUST emit one `info!` line per answered item naming the queried
  content id, the `available` answer, and the REASON for it: `held`, `not-held`,
  `rejected-non-canonical-key` (a `root` that is not canonical 64-hex, refused without a filesystem
  touch), or `store-roots` (a store-granularity query, with the count of held roots).

These lines carry **ids, counts, and outcomes ONLY** — never a served byte, never a proof, never a
secret (§20.4 / the never-log rule). A silent serve is a specification violation: silence is
indistinguishable from a request that never arrived, which is exactly the ambiguity that made the
read-leg bring-up dependent on `tcpdump`.

**A peer-supplied identifier MUST NOT be logged verbatim.** Every id on this surface arrives inside an
untrusted, 64 KiB-capped frame, so a verbatim id would let any peer amplify the operator's log by
~64 KiB per request and — since a JSON string may contain `\n` — FORGE an additional record, including a
counterfeit `served` outcome. An id therefore MUST be recorded only when it is a canonical 64-hex content
id; otherwise a short fixed sentinel (`<non-canonical>` for an unusable id, `<absent>` for one the request
did not carry) MUST be recorded in its place. This applies to `store_id`, `root`, AND `retrieval_key` on
both the `dig.fetchRange` and `dig.getAvailability` paths. Nothing diagnostic is lost: a non-canonical id
could never have named held content, and the outcome/reason on the same line already states why the
request failed.

**Free-form explanatory text MUST be neutralized and bounded.** A `reason` string has no canonical shape
to check against, so it cannot be rejected the way an id is — it MUST instead have every control
character replaced (one glyph per character, so the bound below survives substitution) and MUST be
truncated to at most 200 characters. This covers the `reason` on every `dig.fetchRange` refusal and any
advisory `message` returned to a peer whose text derives from that peer's own bytes — notably the
malformed-DHT-frame reply, where the deserializer quotes the offending input back.

**Both guards MUST be enforced by the TYPE that holds the field, not at the log call site.** The record
structures MUST store the validated/neutralized wrappers, so a raw peer-supplied `&str`/`String` cannot be
placed in a log record however the record is constructed. Sanitizing where a value is REPORTED is not
sanitizing it: the next construction of the same record starts again from the raw value, and a test whose
fixture happens to use a benign id will not notice. A guard that depends on every future caller
remembering it is not a guard.

### 20.3. `control.log.setLevel` — runtime level control

`control.log.setLevel` (§7.4) live-swaps the process level filter via the `dig-logging` reload
handle (`dig-logging` SPEC §5). It is a gated `control.*` method (loopback + control-token or paired
token, §7.2), takes `params.filter` (an `EnvFilter` directive), applies immediately, and does NOT
persist. A missing/malformed directive is `INVALID_PARAMS`; a process without logging installed is
`CONTROL_ERROR`.

### 20.4. `dig-node logs …` verbs

The node mounts `dig-logging`'s shared subcommand verbatim as `dig-node logs …` (also `dign logs
…`), so `logs path`, `logs tail [-f] [-n N] [--level L] [--json]`, `logs level [<filter>]`, and
`logs bundle [-o out.zip] [--all] [--since <dur>]` behave identically to every DIG binary
(`dig-logging` SPEC §8.1). `logs level <filter>` PERSISTS the directive (effective on the next node
start) AND additionally live-applies it to a running node via `control.log.setLevel` (best-effort —
a node that is not running leaves the persisted level in place and reports it, never an error). `logs
bundle` writes a redacted zip safe to attach to a bug report (`dig-logging` SPEC §8.2).

### 20.5. Never-log at source (SPEC §7 of dig-logging)

No secret — a BIP39 mnemonic/seed, a wallet private key, the control token, a paired/session token,
a passphrase — is EVER passed to a `tracing` field or message, at any level. Bundle-time redaction
is only the second line of defence. The transport's per-request logging records ONLY the method name
and a correlation `op_id`, never the request `params` (which for a control/pairing call carry a
token); this is enforced by the request-logger's signature and a never-log regression test.

## 21. Reshare — the whole-`.dig`-module pull (a reader becomes a holder)

A node that reads content MUST be able to become a complete resharer of the capsule it read from. A
resource read fetches only the bytes requested, which leaves the reader faster but the network no
stronger: a `.dig` module is served WHOLE (every retrieval key, with proofs), so a node holding one
resource can serve nothing. The reshare leg pulls the entire module for the generation that was read, and
only then does the node become a holder — so each read leaves the content MORE available than it found it.

This closes the content-replication flywheel: `install -> connect -> discover -> read -> cache -> reshare`.

### 21.1. Wire surface (peer tier)

Two peer-reachable methods, both public-read (unsealed §5.4 exemption — the content is public-by-nature
and content-addressed):

- **`dig.getModuleInfo` `{store_id, root}` → `ModuleInfo`** — the transfer descriptor of a module the
  answering node HOLDS: `total_size`, `module_hash` (SHA-256 of the whole blob, 64-hex), and per-chunk
  `chunk_hashes` + `chunk_lens` in ascending order. `chunk_lens` MUST have the same length as
  `chunk_hashes` and MUST sum to `total_size`. A node that does not hold the module (including a 0-byte
  local file, which is not a module) MUST answer the `RESOURCE_UNAVAILABLE` error, never a descriptor.
- **`dig.fetchModuleRange` `{store_id, root, offset?, length}`** — a byte window of the module blob,
  answered as a STREAM of `RangeFrame`-shaped frames (`bytes` base64), `total_length` on the first frame
  only, terminated by a frame with `complete: true`. A server MUST send a terminating frame even for an
  empty window, or a caller waits forever. A server MAY answer at its own, narrower frame granularity; a
  caller MUST read until `complete`.

**Routing (normative).** `dig.fetchModuleRange` is dispatched by its METHOD NAME, not by request shape:
its response is a frame stream rather than one envelope, and its shape cannot express that. The client
half records the same contract (dig-peer SPEC §3.5), so the two cannot drift.

**Chunking.** The descriptor is one framed response inside the 64 KiB control-frame cap, and each chunk
costs descriptor bytes. A server therefore scales its chunk size with the module — at least 1 MiB, and
always large enough to keep the chunk count at or below 512 — so the descriptor is bounded BY
CONSTRUCTION and no capsule is made unpullable by a framing limit unrelated to its content. A single
`fetchModuleRange` window is clamped to 4 MiB, so one request never sizes the server's work.

**Descriptor cost and the ask deadline (normative).** Answering `dig.getModuleInfo` costs a full read
of the module plus a SHA-256 of every chunk, so its latency scales with the capsule, not with the
request. A requestor MUST therefore bound each descriptor ask and MUST re-ask under a longer bound
rather than treating one elapsed bound as an absent holder: a 135 MB capsule measures ~4 s and a 1 GB
capsule ~30 s on the same host. A server MUST complete a describe it has begun even if the requesting
stream is closed, so that its descriptor memo is populated and the re-ask is answered from memory. The
total a requestor spends on one holder MUST be bounded; an ask that is ANSWERED negatively MUST NOT be
re-asked, since re-asking cannot change a refusal and would delay trying the next holder.

**Descriptor MEMORY, unlike descriptor latency, MUST NOT scale with the capsule (MUST,
dig-node#302).** A server MUST compute the descriptor's digests incrementally, over a buffer whose size
is independent of the module, and MUST NOT make the whole module resident to answer. The two costs are
separable and only one of them is inherent: every byte must be READ to be hashed, but no byte needs to
still be held once it has been. A whole-module read lets one ~100-byte unauthenticated ask commit the
capsule's full size in RAM, which multiplies by concurrent askers and is the same amplification the
4 MiB `fetchModuleRange` clamp exists to prevent on the window path. Incremental SHA-256 yields the
identical digest over the identical byte sequence, so this bounds the server's memory without changing
the descriptor a requestor receives by a single bit.

**A hop that is RELAYING MUST acknowledge, not block (MUST, dig-node#333).** A node asked with
`proxy: true` for a capsule it does not hold pulls that capsule from a holder on the requestor's
behalf. That pull is a whole-capsule transfer and takes arbitrarily long — minutes for a 135 MB
capsule on an ordinary link — while the descriptor ask that triggered it is bounded in tens of
seconds. A hop MUST NOT hold the ask open for the length of the transfer: it MUST answer within a
short grace, and if the capsule has not landed by then it MUST answer
`ContentMissInconclusive` (`-32017`) carrying `error.data.relay_staged_bytes`, its own count of the
bytes it has staged so far, and MUST leave the pull running. A capsule that lands inside the grace is
answered with the ordinary descriptor, indistinguishably from a holder's.

The code is the taxonomy's existing inconclusive-miss code and MUST NOT be a new number: a running
relay is exactly the condition that code names — the availability answer is UNKNOWN and a retry is
meaningful — as opposed to `RESOURCE_UNAVAILABLE`, which settles the question. A requestor that does
not understand `relay_staged_bytes` therefore behaves correctly by default: it retries later.

**A requestor MUST bound a relay wait by PROGRESS and by a ceiling (MUST).** On receiving that answer
a requestor MAY wait, re-asking the same hop on an interval. It MUST continue only while the reported
staged count STRICTLY ADVANCES, MUST abandon the hop after a bounded stall window in which it does
not, and MUST abandon it at a hard ceiling however healthy the progress appears.

Both bounds are required and the ceiling is a SECURITY bound. `relay_staged_bytes` is a hop's claim
about itself, so a hostile hop can fabricate a counter that rises forever and would never stall; only
the ceiling makes the worst case finite.

**The ceiling MUST be accompanied by a per-PULL budget.** A ceiling bounds a wait on ONE hop, and a
pull asks many: a puller's worst case is `descriptor attempts × holders × the per-ask bound`, so
raising the per-ask bound from the descriptor ladder to the relay ceiling multiplies by the holder
count. Where the provider set includes merely-CONNECTED peers rather than only announced holders, that
count is the whole connected pool, and hops each fabricating a byte of progress per poll would hold one
pull open for hours while every one of them stayed inside its individual ceiling. A requestor MUST
therefore charge relay waiting against a budget scoped to the CAPSULE being pulled, and MUST NOT grant
each hop a fresh allowance. Shrinking the per-hop ceiling is NOT an acceptable substitute: an honest hop
relaying a large capsule genuinely needs the full ceiling, and that case is what this path exists for.

**The budget's lifetime MUST be the PULL's.** It MUST be released when the pull ends — in success or
failure — so that a later pull of the same capsule starts with the whole of it. A budget that persists
beyond its pull makes a capsule whose first pull spent it permanently ineligible for the relay path,
and, because the exhaustion is reported as a failure against whichever peer was being asked, it
attributes this node's own earlier spend to that peer. A requestor MUST NOT report a budget exhaustion
in a form that names a peer as its cause.

An idle timeout MUST NOT be used in place of the release. Relay time is charged when a wait ENDS, so a
wait in progress is indistinguishable from an idle entry for up to the whole per-hop ceiling: a timeout
shorter than that ceiling can expire a live pull's budget mid-wait and silently restore the
per-hop multiplication, while one at or above it withholds the budget from the next pull for as long as
the condition it was meant to prevent. The pull boundary is therefore reported by the caller that
drives the pull, never inferred. A requestor MUST NOT treat the count as evidence about the
bytes: the capsule that eventually arrives is verified against the chain-anchored root exactly as a
direct holder's would be (§21.2), so a hop that fabricates its way through a wait still cannot produce
content that passes.

**A relay ask is a SECOND-PASS escalation, and both passes MUST fit in one request (MUST,
dig-node#322).** A requestor MUST spend a PLAIN descriptor round on a `(capsule, peer)` pair before it
sets `proxy: true` for that pair — asking every connected peer to fetch a capsule on this node's
behalf before establishing that no reachable holder exists is the amplification the two-phase design
exists to bound. When that plain round is ANSWERED and the answer is no, the requestor MUST escalate
within the SAME invocation rather than deferring to a later one; a user issuing the documented single
command MUST NOT have to issue it twice. A plain round that was never answered at all MUST NOT be
escalated: a peer that could not answer a plain ask will not answer a relay ask, and re-asking it
doubles the invocation's bound for nothing.

### 21.2. The anchor verifier is the ONLY root of trust (MUST)

Every check before the anchor gate compares peer-supplied bytes against peer-supplied hashes. Those
checks prove SELF-CONSISTENCY, not authenticity: a holder that fabricates a module and describes it
correctly passes all of them. Whatever the anchor gate admits, the node then caches, SERVES, and
ANNOUNCES itself a holder of — so a weak gate makes an honest node an authoritative-looking source of
corrupt content network-wide. Therefore:

1. **The expected generation root MUST be resolved from the CHAIN, before any peer is contacted**, via
   the anchored-root resolver (`verify_pinned_root`, the bounded check). It MUST NOT be taken from, or
   influenced by, the peer that serves the module. If the anchor came from the serving peer, the entire
   fail-closed property is void.
2. **Comparisons MUST be over decoded 32-byte values, never hex text.** Hex is case-insensitive and
   length-forgiving in a way byte equality is not; a peer that influences either side of a TEXT
   comparison gets a bypass for free.
3. **An unparseable or 0-byte blob MUST be rejected explicitly.** Both hash gates pass TRIVIALLY for the
   empty module (SHA-256 of no bytes is a declarable `module_hash`), so the verifier is the only check.
4. **The module MUST commit the store and generation it claims to be.** Its embedded `StoreId` (data
   section 1) and `CurrentRoot` (section 2) MUST equal the store being pulled and the CHAIN's root. A
   section of the wrong width, or an absent one, MUST be rejected — never zero-extended or truncated
   into a comparison it could pass. A module committing a DIFFERENT real generation is a rollback
   primitive and MUST fail closed.
5. A verifier is bound to ONE generation and MUST refuse a pull of any other, so it can never be reused
   to check the wrong anchor.

The production verifier MUST NOT be, or be replaceable by, a fail-open one. dig-download's
`AcceptAnyModuleAnchor` exists only under its `testkit` feature; that feature MUST NOT be enabled on a
production dependency edge.

### 21.3. Becoming a holder — promote, then announce (MUST)

This node's DHT provider records are derived from its CACHE INVENTORY (§19), so the moment a module file
appears at `<cache>/modules/<store>/<root>.dig` this node is advertising itself network-wide as an
authoritative source of that capsule. The promotion ladder is therefore:

```
<downloads>/modules/<store>-<root>.dig.download.tmp   staging
<downloads>/modules/<store>-<root>.dig                verified, NOT yet a holder
<cache>/modules/<store>/<root>.dig                    CACHED == ANNOUNCED AS HOLDER
```

The cached artifact and the `.dig` it was staged from now share ONE extension end-to-end (#1896). A
reader MUST accept a legacy `<root>.module` cache a prior binary wrote — the availability answer, the
serve path, the held-check, and the inventory scan all treat `.dig` and `.module` as the same held
capsule — so an in-place upgrade never drops a holder. At bring-up, BEFORE its first inventory announce,
the node MUST run an idempotent, crash-safe pass that renames each legacy `<root>.module` to `<root>.dig`
(deleting the redundant `.module` where the `.dig` already exists), converging the cache onto the unified
artifact; reader-tolerance covers any file a partial run leaves behind. This is a CACHE-FILENAME
convergence only — it is NOT a change to the immutable `.dig` byte format (§5.1 does not apply).

- **A pull MUST stage OUTSIDE the cache**, so a partial or failed pull is never a candidate for
  announcement — there is no window in which a half-pulled capsule sits at the cache path.
- **The move into the cache MUST happen only on the pull returning success** — never on
  finalize-observed, never on partial staging, never after a failure.
- **Success MUST NOT be taken on faith.** Before the move, the artifact on disk MUST be re-hashed and
  compared against the digest of the bytes the anchor gate actually ADMITTED. Both sides of that
  comparison are then the node's own; a re-hash against the descriptor's `module_hash` would compare
  against a value the serving peer chose. A mismatch MUST abandon the promotion (never "repair" it) and
  MUST NOT announce.
- The move into the cache MUST be write-then-rename, so a reader never observes a partial module at the
  path whose existence is the holder claim.
- **The announce MUST reuse the node's one inventory-reconcile path** (§19), never a bespoke announce, so
  the reshare leg cannot advertise a content-id shape the rest of the node does not.
- **A capsule pulled on ANOTHER node's behalf MUST NOT be announced, and the suppression MUST be a
  property of the CACHED ARTIFACT rather than of the pull that produced it.** A relaying node caches the
  capsule — that is what lets it serve the requestor's windows from the ordinary holder path — but it MUST
  NOT advertise itself as a source of content a stranger chose; doing so reopens, one level up, the
  amplification the non-local reshare refusal closes. Because the announce set is RECONCILED FROM THE
  CACHE, suppressing only the announce that follows the relayed pull is insufficient: any later reconcile,
  from any unrelated cause, would advertise the capsule. The node MUST therefore record the holder claim
  durably beside the cached capsule, MUST write that record BEFORE the capsule becomes visible at the cache
  path, and MUST derive the announceable content-id set — at BOTH store and capsule granularity — only from
  capsules whose recorded claim is a genuine holding. The record MUST NOT outlive the capsule it describes,
  and a later pull of the same generation for the node's OWN sake MUST clear it, so relaying never
  permanently excludes a generation from reshare.
- **Suppression bounds what this node ANNOUNCES, not what it can RESOLVE.** A relayed capsule is
  withheld from the announce set yet MUST remain answerable over the peer capsule-resolve RPC
  (`dig.resolveCapsule`, dig-node-core `SPEC.md` §7.4), which maps a content-key to the
  `(store_id, root, size)` preimage. The two clauses are consistent because the harms differ: an announce PUSHES a holder claim to strangers
  who never asked, which is the amplification this suppression closes, whereas a resolve is PULL-shaped
  — it requires an established peer session and a content-key the caller already holds, and that key is
  a one-way digest the caller can only have obtained from the DHT or from the preimage itself. A node
  MUST NOT filter its resolve answer by holder-claim provenance: a relaying node serves the relayed
  capsule's bytes over the ordinary holder path, so refusing to name content it demonstrably serves
  would withhold nothing while breaking the requestor's own fetch. The resolve answer is therefore
  derived from the CACHE INVENTORY, which is deliberately broader than the announce set; a key this
  node does not hold MUST be absent from the answer rather than an error.
- **A failed pull's staging is kept or erased BY FAILURE KIND, never unconditionally.** A pull that
  failed VERIFICATION — the whole-blob hash gate or the chain-anchor gate — MUST erase its staging
  artifacts: those bytes are attributable only to a descriptor that has been proven false, and leaving
  them would let a hostile holder plant bytes that a later honest range completes around. A pull that
  failed for any other reason — a severed link, a stalled or exhausted holder set, a local disk or
  state-store fault — MUST PRESERVE its staging artifacts and its resume checkpoint together, so the
  next pull of the same generation re-fetches only the missing chunks. Preserving them is safe because
  every staged chunk is re-attributed against the descriptor's per-chunk hash before it is adopted on
  resume and re-fetched if it fails; erasing them unconditionally makes resume unreachable, which is
  measurable only as a byte count, since the retry still succeeds while paying for the whole capsule
  again. A partial that is preserved MUST NOT be promoted, announced, or counted as progress by any
  path other than a resume of the same generation.
- **Abandoned staging MUST be reaped, and total staging MUST be bounded in bytes.** A pull whose process
  dies mid-flight cannot clean up after itself, so the node MUST sweep the capsule-staging directory
  (`<downloads>/modules`, a SUBDIRECTORY — a sweep of the parent directory alone does not reach it) on
  startup and on an interval, removing each staging file older than the staleness TTL together with its
  resume-state sidecar. Because a TTL bounds staging only by what one TTL window can accumulate, the node
  MUST additionally enforce a fixed BYTE ceiling, derived from the per-warm size cap times the
  concurrent-warm cap plus one generation of headroom — a ceiling below that product would evict healthy
  in-flight work.
  Reaping MUST be by age and ownership only, and its permitted scope is narrow BY DESIGN: it MUST NOT
  remove a staging file the node reports as live or paused-resumable (whatever its age), and it MUST NOT
  touch `<cache>/modules` — the operator's held capsules. Those two exclusions are what make oldest-first
  eviction acceptable here: everything in scope is re-fetchable download scratch, so a peer driving reads
  can at worst destroy incomplete partial pulls. Applied to CACHED content the same ordering would be a
  remote eviction primitive, letting a peer walk an operator's own oldest capsules off the disk simply by
  causing reads of others.

### 21.4. The warm is a background pull (MUST NOT slow the read)

The read that triggers a warm MUST NOT wait for it, and a failed warm MUST NOT fail that read: a
whole-capsule pull is orders of magnitude larger than the resource that revealed the capsule, and the
read's latency is user-facing. Serving a module range is paced by the SAME FCFS outbound limiter
`dig.fetchRange` uses (§17) — a whole-capsule pull is the largest thing a node serves, so exempting it
would leave the biggest transfer as the one path able to starve every other peer.

A single read triggers AT MOST ONE whole-capsule acquisition for a `(store, root)` generation, regardless
of tier. Two transports can pull the SAME capsule down — the §21 authenticated whole-store backfill
(`maybe_backfill_capsule` → `gap_fill_generation`, the peerless-network fallback that acquires from the
RPC upstream when no peer serves) and the §21.3 P2P reshare warm — and they are two routes to the same
artifact, so they claim ONE shared single-flight gate keyed `(store, root)`. Whichever leg claims the key
first runs the pull; the other, and any further read of the same not-yet-held capsule, is refused. A
burst of reads across a capsule's resources therefore cannot start N concurrent pulls of the same module,
and the two legs cannot double-pull it between them. The shared gate ALSO bounds how many DISTINCT
generations may acquire concurrently (a fixed cap across BOTH legs, not each in isolation): claims beyond
the cap are SKIPPED, not queued — the next read simply tries again. A store-granularity read starts no
warm: it does not name WHICH generation to pull, and guessing would reshare a capsule nobody asked for.

### 21.5. Dial path (MUST)

A module dial MUST resolve candidate addresses through the shared candidate resolver — IPv6 first, then
IPv4 (§5.2), each socket CONSTRUCTED from a parsed IP rather than a formatted string — and MUST try every
candidate in order before reporting failure, so one unusable IPv6 candidate cannot mask a working IPv4
one. Building a socket address by formatting host and port into a string and reparsing it is FORBIDDEN:
it is invalid for every IPv6 literal, whose grammar requires brackets. The live connected pool is
consulted before DHT hints (a connection-verified address before an untrusted advertisement), and a DHT
failure MUST NOT discard a pool address.

A failure reason MUST NOT embed peer-supplied text; ids reaching a log MUST go through the serve log's
sentinel (§19).

### 21.6. Serve observability

Both module methods emit the §19 serve vocabulary: an INFO outcome line per request (`described` /
`not-held` for the descriptor; `served` with byte + frame counts, or `not-held`, for a range) plus DEBUG
detail. Every id is rendered through the serve log's sentinel, so a peer can neither bloat a log line nor
forge a record. No module bytes are ever logged.

### 21.7. Only the operator's own read may effect the network (MUST)

A read can trigger background legs that spend this node's bandwidth and disk and change what it
advertises network-wide: the whole-capsule warm (`maybe_backfill_capsule`, §21.4) and the reshare pull
plus holder-announce (§21.3). Those legs MUST be reachable only from a read this node's OWN OPERATOR
made. A read that arrived from the network is SERVED normally and effects NOTHING: it starts no warm, no
reshare, no promotion, and no announce. These two legs share ONE single-flight acquisition gate (§21.4),
so the origin/config/held gates on EACH leg run BEFORE it can claim that gate — a gated-out read never
consumes a slot, and the two legs dedup against each other rather than each pulling the capsule.

The rule is not optional hardening. Every peer-facing read surface is unauthenticated in the sense that
matters here — any well-formed self-signed mTLS leaf is accepted (§13), and the plaintext `/s/` surface
carries no token at all — so an ungated leg lets a stranger name a capsule and have this node pull it,
cache it, evict the operator's own content to make room, and then advertise itself as an authoritative
holder of the stranger's choosing, at a cost to the stranger of a few hundred bytes.

Therefore:

1. **Every read carries a read-origin label**, and only a `Local` label may reach a network-effecting
   leg. The label MUST be threaded from the surface that accepted the request down to the leg — a
   function that starts a warm or a reshare MUST take the label as a parameter and MUST NOT assert one.
2. **The label MUST be DERIVED from the accepting connection's real remote address** (loopback ⇒ `Local`,
   anything else ⇒ `Peer`), and from nothing else. Deriving it from the identity of the endpoint or the
   handler is FORBIDDEN, because "this handler is the loopback server" is not a fact: the operator-facing
   `DIG_NODE_HOST` override replaces the loopback bind with any address, and the whole router — the
   JSON-RPC plane, `GET /s/*path`, and the router fallback alike — is served on every listener. The
   Host-header allowlist (§4.2) is a DNS-rebinding defense and MUST NOT be read as an origin check: a
   remote client can send `Host: localhost`.
3. **The derivation MUST fail closed.** A request from which the remote address cannot be recovered MUST
   be rejected, never defaulted to `Local`. An IPv4-mapped IPv6 address MUST NOT satisfy the loopback
   test (IPv6 loopback is `::1` alone), so a remote peer cannot forge a `Local` label by address family.
4. **The operator's off switch still wins.** `DIG_NODE_BACKFILL_ON_MISS=off` refuses these legs even for
   a `Local` read; the origin gate narrows them further and never re-enables them.

The peer-tier read (`dig.fetchRange` / `dig.getContent` on the peer wire) and the local plaintext serve
(`GET /s/…`, and the root-absolute reroot that shares its path) are BOTH subject to this rule — the
serve path reaches the same legs through its P2P tier, so gating one door and not the other leaves the
property unheld.

### 21.8. Landing has a SECOND axis — request provenance (MUST)

A loopback remote address proves the CONNECTION is local; it does NOT prove the OPERATOR authorized the
request. A browser running an attacker's page can issue a cross-site `GET dig.local/s/<capsule>`: the
address is loopback, so §21.7 alone would label the read `Local` and let the attacker's chosen capsule
LAND (warm + reshare + holder-announce). The read itself is harmless — the bytes are public — but the
durable holder side effect is a remotely-triggerable amplification.

Landing therefore gates on BOTH axes:

1. **Every browser-reachable read surface derives a request-provenance label from the `Sec-Fetch-Site`
   request header**, orthogonal to the §21.7 read-origin label. This covers BOTH the `/s/` plaintext
   serve surface AND the `POST /` JSON-RPC read methods (`dig.getContent`, `dig.fetchRange`), whose
   miss-path landing legs (the implicit warm/backfill/reshare fired when the resource is not held
   locally) would otherwise let a SAME-ORIGIN capsule page `POST dig.getContent` and drive landing —
   the loopback address labels it `Local`, so §21.7 alone permits it. The mapping has THREE outcomes,
   because same-origin is not a trust signal on a node that serves untrusted content on its control
   origin (`/s/*` and `POST /` are the same router on the same port, and the store CSP grants store
   pages `script-src 'unsafe-inline'` with `connect-src 'self'`):

   | `Sec-Fetch-Site` | provenance | lands? |
   |---|---|---|
   | ABSENT | `FirstParty` | yes |
   | `none` | `FirstParty` | yes |
   | `same-origin`, `same-site`, any unknown value | `StoreServed` | NO |
   | `cross-site` (case-insensitive, trimmed) | `CrossSite` | NO |

   Absence MUST map to `FirstParty` — non-browser clients (the CLI, the SDK) send no `Sec-Fetch-*`
   header, and treating absence as cross-site would silently stop every CLI/SDK read from landing.
   `none` MUST map to `FirstParty`: it denotes a USER-initiated top-level navigation (address bar or
   bookmark), a page-driven fetch can never produce it, and `Sec-*` is a forbidden header name so page
   script cannot forge it. This is what keeps the reshare flywheel intact — opening a store in a
   browser still lands its capsule, and every subresource is then served from that landed capsule.
   Every other browser-reported value is PAGE-DRIVEN and MUST map to `StoreServed`, including values
   this specification does not enumerate: the unknown arm fails CLOSED. Provenance MUST NOT be derived
   from `Referer` or `Origin` — a page controls its own referrer-policy and can strip the path or the
   whole header, so a `Referer`-derived rule is bypassable by exactly the party it constrains.
2. **A read lands only when it is BOTH `Local` (§21.7) AND `FirstParty`.** A `CrossSite` or
   `StoreServed` request collapses its landing origin to `Peer`: the bytes are served identically, but no warm, reshare, promotion, or
   announce fires. The READ MUST NEVER be blocked, throttled, or altered by provenance — only the side
   effect is suppressed.
3. **The collapse is applied ONCE per landing site via the shared `landing_origin(origin, provenance)`
   fold**, and the collapsed `land_origin` flows to the landing legs; the leaf gates (§21.7) are
   unchanged. On the `/s/` path the fold is applied at the serve seam; on the `POST /` JSON-RPC path it
   is applied at the top of each read handler and the collapsed origin replaces the raw origin at every
   landing site (`content_miss_envelope`/`range_miss_envelope` → the reshare chain, AND
   `maybe_backfill_capsule`) — the raw read-origin is used everywhere else. Each transport threads the
   provenance EXPLICITLY through `handle_rpc`/`dispatch` (a required argument, never inferred): the
   browser-facing HTTP POST classifies the header, every trusted/non-browser caller (the control
   surface, the in-process FFI, the peer-RPC server) passes `FirstParty`. This axis applies only to
   browser-reachable HTTP surfaces; the peer wire remains gated by §21.7's read-origin alone
   (`landing_origin(Peer, FirstParty) == Peer`, so a peer read still never lands). It complements §21.9's
   token-gate on the EXPLICIT `cache.fetchAndCache` landing method.

Honest residuals: a browser predating `Sec-Fetch-Site` (all current major browsers send it) presents no
header and is treated as first-party; and a same-origin store-to-store request within a shared serving
origin is first-party by construction. These are accepted — the axis closes the cross-site CSRF door,
not every conceivable same-origin confusion.

### 21.9. The `cache.fetchAndCache` HTTP surface is token-gated (MUST)

`cache.fetchAndCache` explicitly makes this node fetch, cache, and DHT-announce a capsule of the
CALLER'S naming — the §21.3 holder side effect on demand. Over the HTTP `POST /` surface a loopback
address does not prove operator intent (a cross-site page can POST to `dig.local`), so the method MUST
require the local control token (the `X-Dig-Control-Token` header or `params._control_token`) OR a valid
paired controller token, exactly like a `control.*` method; an unauthorized call is rejected
`UNAUTHORIZED` (-32030) before any landing work. The in-process FFI `cache.*` path is the operator's own
process and MUST stay open — it never traverses this HTTP handler. Anonymous public CONTENT reads remain
ungated.

The same HTTP token-gate MUST also bind `cache.pushCapsule` (§5.5.3, the same holder side effect) and
`cache.listCached` (#2108). `cache.listCached` is a READ, but a HOLDINGS-revealing one: it enumerates the
operator's full cached-capsule inventory (`storeId:rootHash`, sizes, LRU order), which deanonymizes what
content the user has consumed. Over the loopback HTTP surface a cross-site page (DNS-rebinding /
local-service attack) could otherwise POST here and read it, so `cache.listCached` MUST require the same
control/paired token and is rejected `UNAUTHORIZED` (-32030) with no inventory in the body when
unauthorized. The FFI path stays open, and `cache.*` is not routable over the `/ws` transport (the
wallet-backend fall-through has no `cache.*` arm), so the HTTP gate is the only reachable surface.

### 21.10. Reverse-proxy trust caveat (informative)

The `Local` label trusts the loopback boundary. Behind a loopback-terminating reverse proxy every remote
client appears to the node as a `Local` connection; `X-Forwarded-For` is explicitly NOT trusted for the
origin label (a remote client can forge it). An operator who deliberately fronts the node with a proxy
would need a future explicit trusted-proxy configuration — an allowlist of proxy addresses plus an
authenticated proxy-supplied client-address header — before any forwarded address could be believed. No
such configuration exists today; running the node behind an untrusted-header proxy forfeits the origin
gate.

---

## 22. Profile-body sync — the portable DPB on disk, and across the network (epic #3008, W6)

A **dig-profile** is a DID singleton plus a dig-store whose contents are summarised by a
sparse-merkle-tree **root**. Its readable content is a **DPB artifact**, the portable byte format
`dig-social-profile` defines: `magic "DIGP" ‖ version 0x01 ‖ record*`, records ascending and unique,
each `slot_id:u16be ‖ value_len:u32be ‖ value_bytes`.

This section is the node's contract for **holding** a DPB and **propagating** it.

### 22.1. ONE encoding, at every boundary (MUST)

The bytes written to disk, the bytes carried in an opcode-225 frame, and the bytes hashed to the
on-chain root MUST be the **same bytes**. A node MUST NOT re-encode a body at any boundary.

This is what makes the format portable: a body written by one machine is byte-identical to the body
another machine reads, so any node can serve any profile it holds without knowing anything about the
publisher. Re-encoding anywhere would produce a different root and silently break sync.

### 22.2. On disk (MUST)

Bodies live at `<cache>/profiles/<store_hex>/<root_hex>.dpb`, keyed by `(store_id, root)`.

- Writes are temp-file plus atomic rename, so a concurrent reader sees a whole artifact or none.
- Retention is **current plus one**: the body just written plus the most recently modified other.
- The tree is **explicitly OUTSIDE `<cache>/modules/`**. `refresh_inventory` enumerates
  `<cache>/modules/` to build this node's DHT provider records (§19.3); a profile under that tree
  would become a phantom capsule provider record and perturb the reshare flywheel (§21).

### 22.3. The on-chain root is the ONLY authority (MUST)

A node MUST NOT accept a profile body except against a root it resolved from chain **itself**,
through the same anchored-root resolver the read path uses (§14.4). Acceptance is by
`dig_social_profile::VerifiedBody::open`; a node MUST NOT hand-roll the root comparison.

The gate **fails closed**: a chain that cannot be read yields no root, and with no root there is
nothing to compare against, so **nothing is accepted**. A store with no confirmed generation is
likewise a refusal, not a permission.

The same rule binds BOTH entry points. A body offered through `control.profile.putBody` is checked
exactly as a peer's body is: the node resolves the root on chain, requires the caller's claimed root
to BE that root, and only then verifies the bytes against it. **dig-app gets no exemption** — it
holds the key and signs the root (§908), but the bytes reach the node the same way a peer's do.

### 22.4. Verify against the REQUESTED root, never a re-read tip (MUST)

A node MUST only ever request a root it has already resolved from chain, and MUST store the answer
under **that** root.

Re-reading the tip when an answer lands would create two false branches at once: an honest peer
penalized because the chain advanced mid-window, and an ambiguity between a rollback and a race.
Pinning the requested root removes both.

### 22.5. The accept gate, in order (MUST)

Each gate is strictly cheaper than the next, so a flood costs the least possible work:

1. **solicited?** — `(store_id, root, sender)` must be an outstanding request of this node's own.
2. **subscribed?** — the node must want this store (§14.1).
3. **bounded?** — the body must fit `MAX_PROFILE_BODY_BYTES`, checked before any parse.
4. **matches the chain-resolved root?** — §22.3.
5. **persist** the verified bytes verbatim, then **announce once** (opcode 223), excluding the sender.

Re-receiving a body already held is idempotent: no rewrite and no re-announce, so the epidemic
quiesces.

### 22.5b. Originating an announce (MUST)

A node MUST announce (opcode 223) every profile body it holds **whose root the chain has not
retired** (§22.5c), both **immediately** when it accepts one from a local caller
(`control.profile.putBody`) and **periodically** thereafter, to every peer with no exclusion.

The follow-on announce of §22.5 step 5 fires only for a body ingested FROM a peer, so a node whose
only announces were re-announces could never START the exchange: a body handed to it locally, or
held from before its peers connected, would sit on disk unadvertised forever. The periodic announce
is also what makes a peer that connects LATER converge, since the announce it missed is never
replayed to it.

An announce carries no authority, so originating one is safe unconditionally: a receiver ignores a
store it is not subscribed to and resolves the root on chain itself before requesting anything.

### 22.5c. A retired root MUST NOT be announced, and the drift MUST be reported (MUST)

A store's on-chain root can advance while the body a node holds stays where it was. A DPB's root is
a hash of its own bytes, so a body **cannot** be re-anchored under the new root: a root that
advanced means the content changed, and only the publisher can produce bytes hashing to it. A node
therefore MUST NOT attempt any repair, and MUST instead do two things.

**1. Withhold the announce for a root the chain positively contradicts.** Each periodic sweep MUST
resolve the store's current on-chain root — **once per store**, not once per held root, so the two
bodies current-plus-one retention keeps are never judged against two different chain reads — and
MUST NOT announce a held root the chain names as superseded. Retention keeps one predecessor beside
every current body, so this obligation binds healthy stores too.

The withholding condition is a **positive contradiction only**. A chain that cannot be read, and a
store the chain reports as having no confirmed generation, both leave the announce standing. This
direction is deliberately the OPPOSITE of the accept gate's (§22.3), and the asymmetry is the
point: acceptance is irreversible and so fails closed, while an announce carries no authority —
every receiver resolves the root itself before asking for anything — so an unconfirmable announce
costs one ignored frame, whereas silence would take a healthy node off the air for the duration of
a chain outage.

The **immediate** announce of §22.5b needs no check of its own: `control.profile.putBody` has just
required the chain to confirm exactly that root (§22.3), so the root it announces cannot be retired
at that moment. Only the periodic sweep can outlive a root.

**2. Report the drift.** The failure is the ABSENCE of a later write, so it produces no error
anywhere and is invisible to the publisher, who is the only party that can fix it. A node MUST
therefore surface a store whose held bodies are all superseded — in its own log on each sweep, and
in `control.profile.getBody`'s `standing` (§10) — naming the chain's current root and the remedy.

A node MUST distinguish these six standings, because each needs a different remedy and a caller
shown a merged answer cannot choose between them:

| `state` | Means | Remedy |
|---|---|---|
| `current` | the chain's root is held | none |
| `superseded` | bodies held, none at the chain's root | the publisher re-publishes at the chain's root |
| `nothing_held` | the chain names a root, this node holds nothing for the store | publish here |
| `no_generation` | the chain reports no confirmed generation | an unconfirmed mint, or a store id naming nothing |
| `chain_unreadable` | the chain could not be read | the standing is UNKNOWN, not absent; fix chain access |
| `held_unreadable` | the node's own store directory could not be enumerated | what this node holds is UNKNOWN, not absent; fix local disk access. `held_roots` is `null` here, and the chain is NOT consulted |

### 22.6. Penalization is narrow (MUST NOT widen)

A node MUST penalize a peer in exactly ONE case: a body that fails to hash to the root **that peer
was asked for**. A late, duplicate, or unsolicited answer MUST be dropped **silently**.

Widening this turns a multi-peer fan-out into an eclipse primitive: an attacker who can make honest
peers answer late — or who forges an unsolicited frame on a link — could evict every honest peer
from the pool while doing nothing but being slow.

For the same reason a solicitation is a **read, not a take**: a fan-out to several peers stays
answerable by each of them, so a slower honest peer is never reclassified as unsolicited.

### 22.7. Serving (MUST)

An inbound opcode-224 request is answered from disk within an **outbound budget**, because a request
is cheap to send and expensive to answer. The budget MUST be taken only AFTER the artifact is known
to be held, so a flood of requests for content the node does not hold cannot starve the budget for
peers asking about content it does. A held body too large to frame is not sent, and the failure is
visible at the sender rather than silent at every receiver.

### 22.8. Slice 1 binds content to a STORE, never to a DID (MUST)

Nothing in the 223/224/225 frames carries a DID↔store pairing proof, and store descriptions are
forgeable. Therefore:

- the cache is keyed `(store_id, root)` with **no DID index**, and no `by_did` accessor;
- `BLS_G1_PUBLIC_KEY` (0x0010), `PEER_ID` (0x0012) and `KEY_EPOCH` (0x0013) **MUST NOT** be resolved
  out of this cache by any resolver.

Key resolution continues to go through `dig_social_profile::resolve`, which performs the pairing on
chain.

### 22.9. Kill switch

The subsystem is behind `DIG_NODE_PROFILE_SYNC` (default ON, §3.2). Off means the node neither
fetches nor serves profile bodies. Nothing else depends on it having run.

### 22.10. §908 boundary

The node **persists, serves and fetches**. It never signs a profile and never edits one. There is no
seed, private key, signature or unsigned-spend field on any profile method, and there never may be.


<!-- dig_ecosystem#2870: trusted Chia peer add/list/remove (WIP) -->

---

## 23. Automated-spend audit record — accountability for money moved without approval (#376)

The node is permitted to sign certain spends **automatically**, without per-transaction user approval,
because a recurring per-store cycle cannot be gated on a person pressing approve. This section is the
contract for the record that **replaces authorization with accountability**. On a headless install it is
the only surface on which that automation is visible.

The record MUST be owned by the node, not by a client: a record owned by dig-app would leave a headless
node spending a person's money with no trail. `dign` and the app's Activity tab are two VIEWS of the one
record; there MUST NOT be a second record that has to agree with it.

**The file is node-private; the CLI is the contract.** Exactly ONE implementation reads the audit file:
the node's own. Every other view — dig-app's Activity tab included — MUST obtain the record through
`dign spends --json` (§23.6), never by opening the file itself. The file's name, its location and its
on-disk encoding are therefore implementation detail the node may change; the `--json` envelope and the
status tokens are the published contract, and they are what a second view is written against. A reader
that parses the file directly re-creates the two-implementations-of-one-format drift this section exists
to prevent, and does so where the subject is money.

### 23.1. The record models a SPEND, generically

An entry is NOT specific to any producer. It states: `kind` (what for) · `initiated_ms`/`updated_ms`
(when) · `amount_mojos` (how much) · `asset` (which asset) · `authority` (on whose authority) ·
`purpose` (what for, in prose) · `status` (confirmed or failed) · and a chain reference.

`kind` and `purpose` are TWO fields and MUST NOT be conflated into one compound token. `kind` is the
PRODUCER's stable machine word — `"mirror-coin"` for the collateral cycle, never `"mirror-coin.collateral"`
or `"mirror-coin.reclaim"` — and it is what `--kind` filters on. Which DIRECTION a mirror-coin spend moved
money, collateralise or reclaim, is carried in `purpose`, alongside the rest of the reason.

This split is normative and dig-node is authoritative on it, because a compound `kind` destroys a
distinction the producer already makes: it forces every consumer to re-parse a word to recover a field the
record already has, and it makes the filter refuse to name "every mirror-coin spend" without enumerating
the suffixes a future producer has not invented yet. A consumer MUST read `kind` for the producer and
`purpose` for the reason, and MUST NOT synthesise a compound word from the two.

`authority` has two fields: `principal` (whose funds moved and whose standing consent is relied on) and
`grant` (the standing permission relied on, named so an operator can revoke it).

`amount_mojos` is denominated in the entry's own `asset`; an amount MUST NOT be read without it.

### 23.2. Status, and what MUST NOT be claimed

`status.state ∈ { pending, submitted, confirmed, failed, unresolved }`.

* `confirmed` carries `height` and the `coin_id` the spend **created**, INSIDE the status. A record MUST
  NOT be able to hold a confirmation height without a confirmation.
* A spend is confirmed by observing **the coin it created**, never by observing that a funding coin was
  spent. A competing spend of the same funding coin satisfies the latter identically while the intended
  coin never exists. The implementation MUST make the two coins distinct types.
* `unresolved` means the node signed and does not know the outcome. It MUST NOT be reported as `failed`
  (money may have moved) nor as `confirmed`.
* `failed` is NOT uniformly a claim that the money stayed put, and MUST NOT be treated as one. Only a
  failure at the SIGNING stage carries that claim, because no signed bundle ever existed. A failure at
  the `broadcast` or `confirmation` stage happened after a valid bundle existed, so the outcome is
  unknown: such an entry MUST NOT be treated as terminal, and MUST be reconciled (§23.5) rather than
  ignored. A rejection this node observed is not a proof of absence on a network it does not fully see.
* Before confirmation a known coin id is an **intention**. Any surface that shows it MUST mark it as
  unobserved; `chain_reference` carries `{ coin_id, confirmed }` for exactly this.

### 23.3. Entries are unconditional

* The `pending` entry MUST be durable **before** the producer is able to sign. A spend that fails, is
  refused, or never leaves the machine is an ENTRY; a record listing only successes makes a blocked node
  read as an idle one.
* A producer that ends without recording an outcome MUST leave `unresolved`, never silence and never a
  `pending` entry that reads as work in flight.
* **The structural guard:** the signing entry point takes a value obtainable ONLY from the journal call
  that has already written the pending entry. Recording is therefore the shape of the call rather than a
  rule each future producer must remember. A spend reaching chain with no entry is invisible money
  movement.

### 23.4. Storage

An append-only JSONL file, `spend-audit.jsonl`, in the machine-wide state dir (§ the control-token dir,
#501) so the daemon and the operator's CLI resolve the same file across accounts. Both of those are the
node's own code; no other component resolves this path (see the CLI-is-the-contract rule above).

Each line is a full snapshot of one record at one `revision`; the ledger is the fold keeping the highest
revision per `id`. A terminal outcome MUST NOT rewrite the line that recorded the attempt. A line that
cannot be parsed MUST be counted and reported, never silently dropped: a corrupt trail that reads as a
tidy shorter one is the same lie as a missing entry.

There is deliberately **no verb that edits or deletes an entry**.

### 23.5. Reconciliation — local state is never trusted alone

The record MUST be checkable against the chain. `reconcile` takes a chain-side inventory of the coins an
owner holds and reports:

* `unrecorded_on_chain` — coins the chain shows that no entry accounts for. **The alarm**: money moved
  with no trail.
* `missing_on_chain` — confirmed entries whose coin the chain does not show.
* `unresolved` — entries whose outcome the node does not know, still awaiting an answer.

`pending` entries, and `failed` entries at the `signing` stage, claim no coin and MUST NOT produce a
discrepancy. `submitted` entries, `unresolved` entries, and `failed` entries at the `broadcast` or
`confirmation` stage ACCOUNT for their intended coin and are reported under `unresolved`, so chasing one
does not raise a false alarm about its own coin. A spend that failed to broadcast but nonetheless landed
MUST NOT appear in `unrecorded_on_chain`: an entry for it exists, so reporting it as untracked money
movement would be false in the one direction this record exists to be trusted about.

When no chain inventory is available the operation MUST refuse. Reporting "clean" for "I could not look"
is prohibited.

### 23.6. CLI surface

`dign spends [list|show|reconcile]`, read-only and LOCAL — it contacts no node, so it still answers when
the node is stopped or wedged.

* `list` — newest first; `--since-ms`, `--until-ms`, `--store`, `--kind`, `--status`, `--limit`. A limit
  keeps the newest rows.
* `show <id>` — one entry in full. An unknown id is a usage error, not an empty success.
* `reconcile <owner-puzzle-hash>` — § 23.5.

Every verb offers `--json` beside the human output, with stable field names (§6.2). The JSON listing is
`{ path, count, unreadable_lines, spends[] }`, and each spend carries its raw fields plus `status_token`
and `chain_reference`.

### 23.7. `control.spends.list` emits the contract type, not a hand-built object

The `control.spends.list` response MUST be produced by serialising
`dig_node_control_interface::results::SpendsListResult`. It MUST NOT be assembled field-by-field, and a
row MUST NOT be assembled from a type's `Display`.

This is a requirement about the MECHANISM rather than about any one field, because the failure it
prevents is silent. A hand-built object is type-checked against nothing, so it drifts from the contract
one field at a time and each drift ships green: `asset` once went out as the `Display` string `"XCH"` /
`"DIG"` / `"CAT:<id>"` against a contract whose `SpendAsset` is internally tagged and needs
`{"asset":"dig"}`, so no client deserialising into the published type could decode the response at all,
while a client that had reverse-engineered the wire kept working. Serialising the contract type makes a
renamed or dropped field a build error in the node instead of a decode error on somebody else's machine.

The stake is higher here than on other methods. This method is the only sanctioned reader of the
automated-spend record, and that record is what pays for the node signing mirror-coin spends without
per-spend approval. A response no correct client can decode makes the accountability half of that
bargain unavailable to anyone implementing against the published contract.

## 24. Mirror-coin collateral — the requirement, the local margin, and the funding advice (dig_ecosystem#3173)

An advertisement qualifies for an epoch only if it posts that epoch's **collateral**. This section is the
contract for what the node reports about it. It governs three control methods and three `dign` verbs.

**Every figure MUST come from `dig-mirror-collateral`.** The node MUST NOT restate the model's
arithmetic. `required_per_store` is the WHOLE answer: `equilibrium × multiplier − handicap` omits the
floor clamp, and a re-derivation that omitted it would understate what an advertisement must post.
`apply_safety_margin` rounds UP, and a re-derivation that rounded down would post a base unit short of
qualifying. A second implementation of either is a money-path drift bug.

**Units.** Every amount is **DIG base units**: `1 DIG = 1_000`, smallest amount `0.001 DIG`. They are
never mojos — a mojo is XCH's base unit, `1e-12 XCH`, nine orders of magnitude away. The two units MUST
NOT appear in one expression.

### 24.1. The requirement is CONSENSUS; the margin is LOCAL. They are never one value

`control.collateral.requirement` returns the **pre-margin** per-store requirement, which every node
derives identically. It MUST NOT include the local safety margin, and the margin MUST NOT be reachable
from it: returning the margined amount would present one operator's private preference as the network's
price. The margin is served separately by `control.collateral.margin.get` / `.set`.

The census inputs — `stores`, `owners`, `multiplier_micros`, `handicap_dig_base_units` — travel WITH the
figure. A client holding only the number can say the price moved; a client holding the inputs can say
why. `stores` counts qualifying `(owner, store, root)` **advertisements**, never nodes; `owners` counts
distinct owner puzzle hashes and a surface displaying it MUST say "collateralised owners".

`protocol_version` is the version that **computed** the epoch, read from the record — never the newest
version the build implements. The two differ exactly when a node has upgraded mid-schedule, which is the
one case where a client needs the difference.

### 24.2. UNKNOWN is a first-class answer, and it is never a zero

A node that cannot state the requirement MUST return `state: "unknown"` with a `reason`, and MUST NOT
return a zero, a stale epoch's figure presented as this epoch's, or an error a client would render as
"no collateral required". Under-posting costs the operator that epoch's rewards.

The reasons are distinct because their remedies differ:

| `reason` | meaning | remedy |
|---|---|---|
| `not_censused` | this node holds no record for the epoch | run the census |
| `behind_finality_depth` | the epoch's inputs are not final | wait for the chain to settle |
| `record_unreadable` | a record exists and could not be read | re-run the census for the epoch |
| `no_chain_source` | the node cannot see the chain | configure a chain source |

Collapsing them into one "unavailable" hands every client the same unactionable sentence.

**A record the node never wrote and one it wrote and cannot read are different answers**
(`not_censused` vs `record_unreadable`). This is decided by the record file itself, not only by its
contents: a file that is MISSING is `not_censused`, and a file that EXISTS and cannot be read is
`record_unreadable` even when no line was parsed. Reporting an unreadable state directory as
`not_censused` sends the operator to run a census that writes to the very file it cannot read.

**A client MUST NOT render a requirement it cannot decode as a figure.** `state` is an open tag and
the reason taxonomy is open with it, so a client will meet values it does not know — including from
a node newer than itself, since the CLI and the node are installed separately. A client that guards
positively on the states it knows and formats everything else from absent fields renders a real
epoch beside a zero requirement, which reads as authoritative rather than degraded. An answer this
build cannot decode MUST be reported as undecodable, and MUST NOT borrow the `unknown` rendering
either: `unknown` asserts that the node NAMED a missing fact, which an undecodable answer did not.

### 24.3. The epoch is DERIVED from the canonical clock, and never re-derived locally

The mirror-coin epoch schedule is a **wall-clock** one published by `dig-constants`: 7-day epochs
from a fixed genesis. The current epoch MUST be obtained from
`dig_constants::mirror_epoch_at_unix_ms` and MUST NOT be recomputed. The epoch number is an **input
to coin identity** — `dig_mirror_coin::mirror_hint` takes it — so a node computing a different epoch
than its peers does not display a wrong label, it derives different coins and orphans that epoch's
collateral.

Two properties a plausible reimplementation loses, and both are load-bearing:

* the epoch is **one-based** — the genesis instant is epoch 1, not 0;
* it uses **`div_euclid`**, so an instant one millisecond before genesis is epoch 0 rather than
  colliding with epoch 1 as a truncating `/` would.

An instant before genesis yields a non-positive epoch, which is not an epoch. It MUST be reported as
`not_censused` rather than clamped to 1: a machine whose clock is wrong MUST NOT be handed epoch 1's
requirement as though it were current.

**Deriving the epoch is what makes a stale answer unrepresentable.** The requirement is looked up for
the epoch that is current NOW, so a node whose census has stopped running reports `not_censused` for
the present epoch rather than confidently serving a previous epoch's figure. A stored "current
epoch" marker would reintroduce exactly that hazard, because a marker left behind by a stopped census
names an epoch that is no longer current and nothing local can detect it.

### 24.4. The safety margin

Basis points, always — `100` is `+1%`. Never a percentage and never a float: a 1 bp margin (`0.01%`) is a
legal choice and any conversion to whole percent would erase it.

* A stored configuration that **predates** the field MUST load as `DEFAULT_SAFETY_MARGIN_BP` (`100`),
  never `0`. A zero margin is a deliberate choice to post the requirement exactly; reporting it for a
  configuration that never expressed one tells the operator they declined a cushion they were never
  offered.
* `.set` MUST **persist** the value, so it survives a restart. A margin that lapsed to the default on
  reboot would silently change what the node posts, so a failed write MUST NOT be reported as a success.
* A value above `MAX_SAFETY_MARGIN_BP` (`10_000`, i.e. `+100%`) is **REFUSED, never clamped**, and `.set`
  returns what was actually stored. Clamping and returning the clamped value would leave the caller's
  stored intent and the node's behaviour disagreeing on the money path.
* The node is the **authoritative home** for the setting: the flywheel is headless, so a machine with no
  GUI MUST be able to set it. dig-app is a remote control for the same value.

### 24.5. The funding advice — how much to hold, and the states

**Collateral is RECLAIMED, not spent.** Each pass creates the coins for `(store, root, epoch n)` and
reclaims epoch `n-1`; reclaims run FIRST and are never gated on funds (§25.4), so returned collateral funds
the creates behind it. **The steady state is roughly ONE epoch's lock, not one per epoch.** A
recommendation of "requirement x epochs of runway" overstates by the epoch count and tells an
operator to hold many times what they need.

The total is three named terms that sum without double-counting:

```
lock        = pairs_served_by_this_node x apply_safety_margin(required_per_store, margin_bp)
overlap     = the collateral still locked in the epoch being reclaimed
headroom    = what the next `horizon_epochs` could add at the escalation ceiling
recommended = lock + overlap + headroom
```

The **overlap** is the real peak and the term nobody budgets for: epoch `n` exists before `n-1` is
reclaimed, and a reclaim can be delayed or fail.

**`pairs_served_by_this_node` is THIS NODE's own `(owner, store, root)` set.** It MUST NOT be taken
from `control.collateral.requirement`'s `stores` or `owners`, which are network census figures
(§24.1), and it MUST NOT be approximated from the hosted-store list, which is a different set that
merely resembles it. A resemblance is not an identity, and both produce a plausible number.

**Escalation MUST be obtained by stepping `dig_mirror_collateral::step_multiplier` in its high
band**, never from a hand-rolled closed form. A `(9/8)^n` loses two behaviours the controller has:
the step truncates each epoch (0.8x over four epochs reaches 1.281444, not 1.281445), and the result
is clamped at `MULT_CEILING_MICROS`, so a long horizon cannot manufacture headroom the controller
could never produce.

`horizon_epochs` and `escalation_ceiling_micros` are BOTH required alongside the figure. A buffer
without its horizon is a magic number, and a horizon without its ceiling cannot be reproduced. The
ceiling is a **worst case, not a forecast** — inside the dead band the multiplier does not move.

The states, of which only two leave an epoch uncovered:

| state | meaning | `is_shortfall()` |
|---|---|---|
| `short_now` | cannot cover the current epoch; roots are already uncollateralised | **yes** |
| `dangerously_low` | covers now; could not cover the next epoch at the escalation ceiling | **yes** |
| `below_recommended_buffer` | every epoch covered, no cushion | **NO — readout only** |
| `funded` | at or above the recommendation | no |

`below_recommended_buffer` MUST be excluded from `is_shortfall()` and MUST NOT raise a notification.
Every epoch it covers *is* covered; a healthy node sits there much of the time, and a recurring alert
an operator learns to dismiss teaches them to dismiss the two above it.

### 24.6. UNKNOWN must be UNREPRESENTABLE as a number

`control.collateral.buffer` is a **separate method** from `control.collateral.requirement`, not a
widening of it: the requirement is consensus-derived and identical on every node, while the buffer
depends on this node's own served set, an operator preference, and a horizon this node chose. The
funding state is **carried, not re-derived by clients** — two clients deriving it will disagree, and
the one that disagrees about a funding warning is the one an operator acts on.

The buffer answer is a **tagged variant**: the unknown case carries `state` and `reason` and **no
numeric field at all**. This is a shape requirement, not a convention — a struct with optional
numbers can hold a `0`, and a zero buffer reads as *no buffer needed*.

| `reason` | the missing fact |
|---|---|
| `requirement_unknown` | the node cannot state this epoch's per-store requirement |
| `served_set_unknown` | the node cannot enumerate the roots it serves |
| `reclaim_state_unknown` | the node cannot tell which of last epoch's coins are reclaimed |
| `balance_unknown` | the operator's spendable $DIG is not known to this node |

`requirement_unknown` is distinct from the rest and from §24.2's reasons on purpose: a missing
requirement is a NETWORK gap, while the other three are LOCAL. Reporting one as the other sends the
operator to fix the wrong thing.

**None of these has a counterpart in §24.2's census taxonomy**, which is the structural reason the
buffer is its own method rather than a widening of the requirement: collapsing `served_set_unknown`
into `not_censused` reports a missing LOCAL fact as a missing NETWORK one and sends the operator to
fix the wrong thing.

This is a live hazard, not a theoretical one, because **an unknown and a genuine zero produce
identical arithmetic**: a served count read as zero yields a `0.000 DIG` recommendation that every
balance clears, so a node that could not tell how much it owes would report "funded". A surface MUST
also distinguish "nothing to collateralise" from "your funding is sufficient" for the same reason.

A malformed operator-supplied balance is REFUSED, never parsed as zero, which would report
`short_now` over a typo. Amounts are scaled by integer arithmetic: `0.001 DIG` steps are where an
`f64` starts rounding.

### 24.7. The `dign` verbs

* `collateral requirement` — §24.1/§24.2. Prints the reason and its remedy on `unknown`, never a zero.
* `collateral margin [set <tight|default|generous|BP>]` — §24.4. A preset resolves to
  `dig-mirror-collateral`'s own constant, never to a number spelled out in the CLI; a second spelling is
  how two surfaces post different amounts for one choice. An unrecognised word is REFUSED, never treated
  as the default.
* `collateral buffer [--roots <N>] [--balance <DIG>]` — §24.5/§24.6. With no operands it asks the
  node, which is the authority on its own served set, preference and balance. The operands are an
  OVERRIDE, so a person can get a figure before the node can enumerate its served set; they are never
  a fallback the node applies itself. Either way it states an AMOUNT to add, not an adjective, and
  shows the working: roots served, per-store requirement, margin, the three terms, and the horizon
  with its ceiling. When the root count came from `--roots`, the output MUST say so: the operand and
  the node's own measurement otherwise render identically, which would make an operator's guess
  indistinguishable from a measurement in every figure derived from it.

* `collateral history [--epoch <N>]` — §24.8. Read from this node's own record store rather than
  over a control call, so it answers on a node that is not running. Each line names the provenance,
  because a bootstrap record, a censused one and one adopted from untrusted peers are three
  different claims. An epoch never recorded MUST read as NOT RECORDED, distinctly from one recorded
  and no longer readable.

Every verb offers `--json` beside the human output, with stable field names (§6.2).

### 24.8. The per-epoch record store

The node MUST persist one record per collateral epoch, in `collateral-epochs.jsonl` under its
machine-wide state directory, one JSON object per line. Each record carries the consensus
`EpochRecord` — the census inputs (advertised stores, collateralised owners, multiplier, handicap),
the derived `required_per_store_dig_base_units`, and the `protocol_version` that computed it — plus
two node-local fields:

* `census_height` — the block height the census behind the record was taken at, or `null` at epoch 1,
  which is derived from nothing and was taken at no height. `null` MUST mean "no census was taken",
  never "the height was lost".
* `provenance` — `bootstrap`, `censused`, or `adopted_from_peers` with the counts that agreed and
  answered. The three are different claims about what this node verified and MUST NOT be rendered
  identically.

The census height MUST NOT enter the arithmetic. Two nodes reading the same chain at the same height
derive the same record whether or not either records the height; it is carried so a disputed census
names the block it can be re-run against.

**Historical records are permanent and immutable.** A record that DIFFERS from one already held for
that epoch MUST be refused and the held one kept. A node that let the newest writer win could be
walked off the network's history one epoch at a time by whoever spoke last, and every figure below
it — including the amount of $DIG the operator posts — would follow. An identical record offered
with stronger provenance MAY be recorded, because the consensus figures do not move; the reverse
MUST NOT be, because evidence does not weaken on re-offer.

**Immutability MUST NOT seal an under-count this node produced itself.** Exactly one differing pair
beyond §24.10's may supersede: a record this node censused MUST be replaced by a LATER census OF ITS
OWN, of the same epoch, taken at the SAME census height, that counted strictly MORE stores. Both
sides MUST carry `censused` provenance, and both census heights MUST be present and equal.

The repair MUST NOT be able to move the price DOWN. Every counted figure in the incoming census --
`stores`, `owners` and `locked` -- MUST be non-decreasing against the held record, and the derived
`required_per_store` MUST be non-decreasing as well, compared DIRECTLY rather than inferred from
those inputs. Constraining `stores` alone is not sufficient and MUST NOT be implemented: the
requirement is derived from the multiplier and the OWNER count, so a record counting one more store
while reporting fewer owners would satisfy a stores-only rule and still cut what every operator
posts. A re-census failing any of these conditions MUST change nothing.

Constraining the counted figures is likewise not sufficient, and the `required_per_store` clause
MUST NOT be treated as redundant with them. The multiplier's volume signal is locked collateral
DIVIDED BY the store count, so counting more stores LOWERS that signal and can drop saturation
across a dead-band edge, stepping the multiplier down. A re-census with `owners` and `locked` EXACTLY
EQUAL to the held record -- satisfying every counted clause, collapsing nothing -- can therefore
still cut `required_per_store` by as much as 57.7%. Only the direct comparison of the derived figure
refuses it.

The direction is the whole of the rule, and it is bounded by an assumption that MUST be stated
rather than assumed. A chain view that is merely DEGRADED can only omit coins, never invent them:
reporting one more requires a real coin to have been posted, while dropping one requires only
silence. Admitting only the upward direction therefore keeps a briefly-degraded read from becoming
permanent without letting a degraded source talk the requirement down. This is NOT a claim that a
census is unforgeable. Candidate coins are authenticated against their own self-consistency and not
against consensus -- no header, no inclusion proof -- so a source that FABRICATES rather than
miscounts is outside what this rule constrains, and is tracked as its own defect. Because a record
may only ever be replaced by one counting strictly more stores, the relation remains a strict
one-way ladder and no ordering over records has to be invented.

This does NOT let a peer supersede anything: both sides must be `censused`, and §24.10's discipline
stamps every record reachable from the network `adopted_from_peers`.

A node MUST record the epoch-1 record at start-up if it holds none. It depends on nothing, so every
node can produce it, and it is the base case that makes the recurrence well founded.

**A record whose `protocol_version` exceeds what the build implements MUST NOT be served as
authoritative** — not by `control.collateral.requirement`, not by `dig.getCollateralEpoch`, and not
into a verification. Every field of such a record parses, so nothing downstream would question its
figures.

### 24.8a. Producing a record: the census

A record for an epoch after the first MUST be produced by counting the chain, and by nothing else.

The node MUST obtain the three census inputs from `dig_mirror_coin::census`, at the height
`dig_mirror_coin::census_height` derives for that epoch — the first transaction block at or after
the epoch's start instant — and MUST derive the record with
`dig_mirror_collateral::EpochRecord::advance`. It MUST NOT restate either. A census height chosen
any other way is a fork, because every node must reach the same height without coordinating.

The chain reads MUST be served through a `dig_chainsource_interface::ChainSource`. The node MUST NOT
open a second connection to the chain for this purpose: it takes a `ChainSource` view of the one
transport that already serves its wallet reads, so a node holds ONE peer pool.

**One pool is not one notion of the peak, and this node has three.** The wallet's peak is settled by
NC-12 agreement across the full nodes this node dialled itself, and their failure to agree is
reported as not knowing. The census's peak is not: it is read through the `ChainSource`, whose router
asks `api.coinset.org` FIRST and consults this node's peers only when that read fails — so on a
reachable oracle the census's peak is one HTTPS endpoint's answer, and when the oracle is
unreachable it is a peer-tracked value carried with NO agreement step. It is that peak the
`CENSUS_FINALITY_DEPTH_BLOCKS` refusal below is measured against.

A census provider MUST therefore be classified by what it can REACH rather than by its type: a
fabric that can fall through to the oracle shares the oracle's independence group, however many
peers it holds. A node MUST NOT count such a provider as an independent chain source, and MUST NOT
describe the census's peak as corroborated.

**The walk is sequential.** Epoch *n* is derived from epoch *n-1*, so the node computes each
intervening epoch in order from the newest record it holds. It MUST NOT skip forward to the current
epoch, and it MUST NOT derive a successor from a record whose `protocol_version` exceeds what the
build implements — the ceiling of §24.8 applies at this boundary too.

**A census that could not be taken MUST record nothing.** Each refusal is reported with its own
reason and its own remedy:

| the census stopped because | remedy |
|---|---|
| a chain read could not be answered | reach a chain source |
| the chain has not yet reached the epoch's start | wait for a block |
| the census height is not yet buried to `CENSUS_FINALITY_DEPTH_BLOCKS` | wait |
| the candidate population exceeds what can be authenticated | refused whole; never censused as a prefix |
| the predecessor record is absent, unreadable, or names an unimplemented ruleset | that epoch first |
| the store already holds a DIFFERENT record for the computed epoch that the §24.8 repair does not admit | the held record stands |
| the controller refused to derive the record from the census | its own reason, reported verbatim: the census is not the successor epoch, no activation row governs that epoch, or the version is unimplemented |
| the record store could not be read or written | the state directory |
| the store's own line for the computed epoch cannot be read | repair or remove that line |

The last of these MUST be detected BEFORE the chain is read. An unreadable line is invisible to the
scan that answers "the newest epoch held", so a node that did not check would recensus that epoch on
every attempt — the whole population and its spend executions — only to fail at the write, forever.

None of these MUST EVER become a figure — not a zero, not a default, and not the neighbouring
epoch's answer. The store's own absence then surfaces through §24.2's `unknown` with its reason,
which is the only answer such a node can defend.

**A census that counted nothing MUST say what it examined.** A `stores` of zero is produced
identically by an empty network, by a source answering at a puzzle hash other than the one it was
asked for, and by a source that could not supply the creating spends its candidates needed. Those
call for opposite responses and only the first is a fact about the network, so for every epoch it
records a node MUST report the census's examined count and its per-rule exclusion counts alongside
the recorded figure. Reporting the figure alone renders a broken instrument as an answer.

**A node MUST re-census the target epoch it already holds, and MUST NOT re-census any epoch before
it.** The current epoch's record is the one still repairable under §24.8, and a walk that stopped
looking the moment it had an answer is what made a single degraded read permanent. So the steady
state costs one census of ONE epoch per pass. Every earlier epoch MUST be computed exactly once,
which is what keeps a node catching up across many epochs from paying for the repair.

A re-census that comes back SMALLER MUST be reported as the store conflict it is, never silently
discarded: the node's stored answer and its current chain view disagree about a block that is
already buried, and the higher held record stands.

### 24.9. Serving an epoch to a peer

`dig.getCollateralEpoch` is an OPEN node method taking `{ epoch }` and returning `{ record }` or
`{ record: null, reason }`. It is unauthenticated because an epoch record carries nothing secret and
a caller verifies what it receives by re-derivation whatever the source, so authenticating the
server would buy nothing the verification does not already give.

Each way of not producing a record MUST be a distinct named `reason` — `invalid_epoch`,
`not_recorded`, `record_unreadable`, `unimplemented_ruleset` — never a zero, a default, or a
neighbouring epoch's record. The caller is deciding whether to re-census a week of chain history,
and the three refusals mean "ask someone else", "this node is broken", and "your ruleset is newer
than mine".

### 24.10. Adopting an epoch from peers

Every dialled peer is untrusted (NC-12), and the requirement a record names is the amount this
operator posts as collateral. **A record from a peer is adopted because it is recomputable, never
because the peer is trusted.**

A receiving node MUST re-derive a candidate from a predecessor it already holds, through
`EpochRecord::advance`, and MUST require every field of the result to match — not only the
requirement. It MUST NOT restate the model's arithmetic to perform that check. Consequently a peer
cannot lie about any derived quantity while keeping its census inputs, cannot lie about the ruleset,
and cannot skip an epoch.

A receiving node CANNOT check the census inputs against the chain. A record whose arithmetic is
impeccable and whose inputs are fiction is indistinguishable from an honest one by re-derivation
alone. The sample is the only defence against that residue, and it is bounded:

* The sample MUST be sized by `dig_mirror_collateral::sync_sample_plan` against a chain-derived
  owner population. A node that does not know the population MUST NOT adopt; a sample drawn from an
  unknown population supports no confidence claim.
* Below `SYNC_MIN_POPULATION` the plan is advisory and the node MUST derive from chain instead.
* Adoption requires the plan's strict two-thirds agreement threshold, tallied over the FULL record.
  A plurality MUST NOT be adopted: the plurality is what an attacker holding a minority of
  identities is trying to produce.
* The threshold is a supermajority **of the planned sample**, and the plan caps `sample_size`, so
  the threshold does not grow with the population. A node MUST therefore refuse a sample with more
  distinct responders than `sample_size`, whole and untrimmed. Counting a fixed threshold against a
  larger responder set would adopt a plurality, which the clause above forbids.
* More distinct responders than the chain-derived population is a detectable identity lie and MUST
  refuse the whole sample rather than trim it.
* A responder that answers twice, differently, MUST have both answers discarded.
* Every epoch after the first is produced by a census, so a candidate for an epoch greater than 1
  that carries no census height MUST be refused. A node MUST NOT treat an absent height as a check
  that does not apply, which would let a responder opt out of the advancing requirement by omitting
  a field.
* The census height is this node's bookkeeping and is excluded from the tally key, so agreeing
  responders may still differ on it. A node MUST carry the LOWEST height offered by the agreeing
  cohort. Taking any responder-chosen height would let one member of an honest cohort name a height
  no later census can advance past, denying every subsequent epoch. **This clause and the
  missing-height refusal above are only correct together**: an absent height orders below every
  present one, so taking the lowest without refusing absent heights would let one responder strip
  the height from an honest cohort and disable the next epoch's advancing check instead.

**A known limitation, stated rather than assumed away:** the plan counts distinct collateralised
owners, while a node samples distinct peers, and a peer's owner attribution is not proven on this
path. One adversary holding many peer identities therefore looks like many owners to the sampler.
This is why adoption is never load-bearing — the sample buys the ability to skip an expensive
historical re-derivation, never the right to be wrong — and why a node that can census an epoch
itself MUST prefer its own computation.

Preferring its own computation is a requirement on the STORE, and it binds precisely where the two
disagree. §24.9 makes a held record immutable so that no peer can walk a node off the network's
history; that immutability MUST NOT also prevent a node correcting itself. A record held with
`AdoptedFromPeers` provenance MUST be superseded by one this node censused for the same epoch, even
when the two records differ. The only other pair that may supersede is §24.8's repair of this node's
own earlier census by a later one of its own counting strictly more stores at the same height; any
other differing record remains a conflict.

**What keeps a peer off the superseding side is a discipline, not a type.** `StoredRecord` carries
its provenance as an ordinary deserialisable field, so a wire record naming `censused` decodes as
`Censused` and would supersede if it were handed to the store unchanged. It is not: the adoption
path DISCARDS whatever provenance a responder sent and stamps `AdoptedFromPeers` from its own tally.
Any future path that admits a record from the network MUST do the same. A node MUST NOT treat a
record's own claim about its provenance as evidence of that provenance.

**A second stated limitation:** re-derivation is only as sound as the oracle it runs through. This
node trusts `dig_mirror_collateral::EpochRecord::advance` to be the network's arithmetic, and checks
a candidate by comparing against what that function produces. A defect in `advance` is therefore not
detectable on this path — it would be reproduced identically by every node that verified through it.
The mitigation is that `advance` is the single published implementation the whole network derives
from, so a divergence is a release-level event rather than a per-peer one.

### 24.11. Retention

Retention is **off by default**: a node keeps every epoch forever unless the operator sets
`retention_epochs` in `collateral.json`. The model's premise is that any node can recompute any past
epoch and reach the same answer, so a default that discarded history would erode that on every node
at once.

`retention_epochs` counts back from the current epoch inclusive. A value of `0` MUST read as the
default rather than as "keep nothing", which would discard the epoch currently in force. **Epoch 1
MUST NOT be pruned under any policy**: it is the base case every verification walk terminates at, so
a node that discarded it could no longer check anything a peer offered it.

---

## 25. Mirror-coin lifecycle — presence on disk made true on chain, signed by the node (dig-node#377)

The node advertises each `(store, root)` it serves by locking $DIG in a mirror coin, one coin per
`(store, root, epoch)`, and it signs those spends ITSELF, without per-spend approval. This section is
the contract for that lifecycle: the invariant it maintains, the exact boundary of the signing
authority, the reconcile pass, and how the authority is revoked. §23 is the accountability contract
every spend here is subject to; §24 is where the amount comes from. Spend construction is owned by
`dig-mirror-coin` — nothing in this repo assembles a mirror spend, a CAT wrapper, or a memo layout
itself (SYSTEM.md §4.1).

> **IMPLEMENTATION STATUS — read this before relying on any clause in §25.** This section is
> normative in full and is written in the present indicative throughout. At this head **the
> deciding and the ORDERING halves exist, and nothing RUNS them** — no pass is constructed, so no
> observation is ever made and no spend is ever attempted. Satisfied by code today, and *only* this:
>
> * §25.2's structural bounds on the signing authority — `MirrorSpends` and its two producers
>   (`mirror/spends.rs`); and in `mirror/signer.rs`, the fee ceiling, the refusal of spends belonging
>   to another wallet, and the one-record-per-signature audit entry whose intent is derived from the
>   spends. All four read the artifact rather than a value passed beside it.
> * §25.3's pricing rule and §25.4's step-3 planner, as **pure functions** over supplied
>   observations (`mirror/plan.rs`, `mirror/pass.rs`), including §25.7's switch semantics and
>   §25.9's decision directions.
> * §25.5's stability rule, as a **pure tracker** (`mirror/presence.rs`), and §25.7's persisted
>   `collateral.json` switch.
> * §25.4's **execution rules** — steps 4, 5 and 6 — as `mirror/runner.rs`: reclaims are performed
>   before any create and are never gated on funds; the create loop stops cleanly at the end of the
>   affordable prefix or at the first create that errors; and the in-flight set is re-derived from
>   the audit record on every pass, which is restart-safe because the record carries the bond
>   `(store, root, epoch)` structurally (`spend_audit::AuditedBond`).
> * §25.1's **`Relayed` exclusion**, applied at the point of observation
>   (`mirror::runner::split_by_provenance`) and expressed in the types thereafter: `PassInputs::held`
>   and `::relayed` are separate fields, so no relayed capsule can reach the create path.
> * §25.8's **vocabulary**, as `mirror::pass::BondState`: `disabled` (the node-wide switch),
>   `unadvertised` (that switch ON with nothing publishable to advertise), `withheld` (`Relayed`
>   provenance) and `reclaiming` are four distinct states, agreeing with
>   `dig-node-control-interface` 0.28.0's tokens, which the node now ADOPTS. `withheld` has a real
>   producer, the relayed set, rather than being unreachable from a `Held`-keyed derivation.
> * §25.8's **method and verb**: `control.mirror.bondStates` is served (`control.rs`) and
>   `dign mirror bond-states` is the verb. The wire mapping, the whole-set locked total, the
>   canonical-key ordering and the paging are `mirror/states.rs`; `BondState::FundsUnknown` maps to
>   `deferred { balance_unreadable }` per row, never to `unfunded`. The method now ANSWERS: it
>   serves the observation the last pass published (`mirror/lifecycle.rs`), and `unknown
>   { chain_unreadable }` remains only for a node whose first pass has not completed.
> * A **production `MirrorEffects`** (`mirror::lifecycle::NodeMirrorEffects`) and a SCHEDULED pass
>   (`server::spawn_mirror_passes`, on `dig_constants::MIRROR_ROUND_LENGTH_MS`). The operator wallet
>   is opened ONCE at bring-up under the device key; a §16.4 `Locked` or `Orphaned` wallet yields no
>   signer, and the lifecycle then OBSERVES without spending rather than degrading. `dig_mirror_coin::list`
>   is called, and an INCOMPLETE inventory (`MAX_CANDIDATES` truncation, unresolved candidates)
>   aborts the pass rather than under-reporting locked money.
>
> **Two things in §25 remain PENDING**, tracked as
> <https://github.com/DIG-Network/dig-node/issues/412>:
>
> * **CREATES select their collateral from the OPERATOR wallet, and are refused for want of an
>   ADVERTISED URL.** `mirror::funding::select_operator_dig_cats` scans the chain at the CAT wrapping
>   of this node's operator puzzle hash under `dig_mirror_coin::DIG_ASSET_ID`, withholds coins
>   committed to a bundle whose audit record is not terminal, selects largest-first, and
>   reconstructs each selected candidate's lineage from its creating spend — refusing the WHOLE
>   selection on a shortfall, an unauthenticatable candidate, an unreadable chain, or an unreadable
>   audit record, never funding a smaller coin (dig-node#421). The reservation is FED by every
>   successful broadcast and not only by one whose created coin is derivable: on a `broadcast` that
>   reaches the mempool, `mirror::lifecycle::NodeMirrorEffects::sign_and_broadcast` records a
>   `spend_audit::Submission` UNCONDITIONALLY, carrying the coins the signed bundle consumes. The
>   coin CREATED is a separate, optional field of that submission — a create names none, because its
>   output coin takes its parent from whichever input the builder drew it from and this node does not
>   derive it — so an underivable target no longer suppresses the record of the coins consumed, and
>   `control.mirror.*` and `dign spend-audit` MUST show a create's consumed coins rather than an
>   empty list. **Two creates MUST NOT select the same coin**, whether or not they fall in the same
>   pass, and the two halves of that are separate mechanisms: ACROSS passes the durable journal
>   above is re-read before each pass, and WITHIN one pass — where a pass emits a create per bond of
>   the affordable prefix — `NodeMirrorEffects` extends its own committed set from each bundle that
>   reaches the mempool, so a later create in the same pass selects against what the pass has
>   already spent. The journal alone does not cover the second: it is read once, before the pass,
>   and the chain reports a broadcast coin as unspent for the whole confirmation window. What is
>   still missing is the
>   advertisement: `dig_mirror_coin::create` requires at least one URL its store can be fetched
>   from, this node has no configured public name, and `NodeMirrorEffects::create` therefore refuses
>   by name BEFORE any chain read (dig-node#426). **RECLAIMS are implemented** and are supported at `fee = 0` with
>   no fee coins, which is §25.4.4 — and are never gated on any funding read, including the
>   committed-coin read.
> * **§25.10's verification of OTHER peers' claims is BUILT BUT INERT — no claim is verified on a
>   running node today.** The mechanism is present and wired: `dig-node-core`'s `mirror_bond` (the
>   three verdicts and the ranking locator, installed inside `NodeContent::new`) and
>   `dig-node-service`'s `mirror/bond_verify.rs` (the chain read, installed on the running node by
>   `spawn_bond_verifier_install`). But this node has no sound source for the coin-to-peer binding
>   §25.6a requires, so `bonded` is unreachable for every input, the chain read is short-circuited
>   before it is paid, and every holder receives the same verdict — the ranking is a no-op on every
>   slate. **A reader must not take this bullet as saying collateral is enforced; it is not.** The
>   binding is tracked as <https://github.com/DIG-Network/dig-node/issues/473>, and promotion
>   becomes reachable the moment it lands, with no further change here. What is verified once it does
>   is a peer's claim; this node still attaches no pointer of its own, per the next bullet.
> * **§25.6's DHT pointer is not attached.** `ProviderRecord::unverified_mirror_coin_id` lives in
>   dig-dht 0.15, and `dig-download` 0.21.0 and `dig-peer-selector` 0.10.0 both require
>   `dig-dht ^0.13` — semver-incompatible on a `0.x` line, so taking 0.15 here would resolve two
>   dig-dht lines. Tracked as <https://github.com/DIG-Network/dig-node/issues/422>.
>
> So a reader MUST NOT infer that any coin is CREATED at this head, and MUST NOT infer that a mirror
> coin id reaches the DHT.
>
> **A clause not named in the list above MUST be read as pending, whatever its grammatical voice**,
> and the list is to be read NARROWLY: where an entry names a file or a function, it satisfies the
> clause only to the extent that named code reaches. The default is deliberately pending rather than
> satisfied — a per-clause list of what is missing has to be complete to be safe, and this one only
> has to be complete about what is *present*.

### 25.1. The invariant

> **PENDING — the invariant is stated, and nothing maintains it at this head.** Neither side is
> observed: `mirror::runner::MirrorEffects` DECLARES both observations and nothing implements it, so
> `cache_list_cached()` is not read by this module and `dig_mirror_coin::list` is not called anywhere
> in this repo. So a reader MUST NOT infer that a coin's existence tracks a `.dig`'s presence today;
> the biconditional below is the obligation
> <https://github.com/DIG-Network/dig-node/issues/412> discharges.
>
> **The `Relayed`-is-never-advertised rule IS satisfied by code, and it is the load-bearing one.**
> `mirror::runner` splits the observation by `CapsuleProvenance` at the point it is made
> (`split_by_provenance`) and hands the two halves to `PassInputs` as SEPARATE FIELDS, so the create
> path is structurally unable to see a relayed capsule and no caller can substitute an
> already-filtered set. This is the single point at which another party could influence what this
> node spends its own money on, since a `Relayed` capsule arrives on somebody else's behalf — which
> is why the exclusion is a shape rather than a filter someone remembers to apply. What remains
> PENDING is the OBSERVATION itself: no implementation of `MirrorEffects` reads `cache_list_cached()`,
> so the split has no live input yet.

> **A mirror coin owned by this node for the CURRENT epoch exists ⟺ the `.dig` for that
> `(store, root)` is on disk with `Held` provenance.**

Both directions are normative, and they fail in different directions:

* **`.dig` held → coin MUST exist.** Without it the node serves content it is undiscoverable and
  unrewarded for. A missed create costs opportunity only — money stays in the wallet.
* **`.dig` gone → coin MUST be reclaimed.** A live coin advertising content this node cannot serve is
  the PENALISED state, so reclaim is loss avoidance, not cleanup, and the reclaim path is held to a
  higher standard of reliability than the create path.

The disk side of the invariant is `Node::cache_list_cached()` filtered to
`CapsuleProvenance::Held`. `Relayed` capsules are servable but NEVER advertised (dig-node#276);
collateralising one would stake $DIG on a claim the node deliberately does not make. A capsule that
has not landed and verified is not in the inventory at all, so "never advertise a store you cannot
serve" holds structurally rather than by a sync-state check.

The chain side is `dig_mirror_coin::list`, keyed on the owner puzzle hash, with ownership read from
each coin's lineage proof. **No local bookkeeping is ever a source of truth for what is bonded** —
the legacy's authoritative local `.json` stranded collateral when it was lost, and this design makes
that unrepresentable: the reconcile's only inputs are the disk and the chain.

### 25.2. The signing authority — what §908 still forbids, and what this section permits

**Unchanged, and this section does not weaken any of it:** the node holds no user seed and no user
spend key (§16.3, §18.20, §18.24); no dapp/RPC/control surface can obtain a signature over
caller-supplied spends from the node's keys; `control.wallet.broadcast` remains a relay for bundles
somebody else signed and carries no signing parameter (§4-method table).

**What this section permits:** the node signs mirror-coin CREATE and RECLAIM spends, automatically,
with the keys of its OWN operating wallet — the §16.4 autoseed identity, which is machine custody,
not user custody. The user funds that wallet (the dig-app deposit flow); money deposited there is
money placed under this section's standing authority.

The authority is bounded four ways, and every bound is stated so a reader can check it:

1. **By reachable spend shape.** `MirrorSpends` is a newtype with no public constructor, no
   `Default`, and no conversion from `Vec<CoinSpend>`. Its only producers are `build_create` and
   `build_reclaim`, thin wrappers over `dig_mirror_coin::create` / `::reclaim` that add no
   conditions, alter no amount and change no destination. The signer's ONLY public entry point is
   `sign(&MirrorSpends, &SpendJournal) -> Result<(SpendBundle, RecordedSpend), SignError>`, and it
   MUST refuse spends whose owner puzzle hash is not its own wallet's — the builders take a
   `synthetic_key` while the signer signs with its own, and nothing else relates the two.
   There is no method on this path that accepts an arbitrary
   `CoinSpend`, so widening the authority requires adding a producer — a visible, reviewable edit to
   the one file whose purpose is to say what may be signed.
2. **By destination, structurally.** A create's collateral lands at the $DIG CAT construction around
   `dig_mirror_coin::mirror_coin_puzzle_hash()`, with change returned to the node's own puzzle hash;
   a reclaim recreates the FULL locked amount at the owner's own puzzle hash and is refused
   (`NotOwner`) for any coin the node does not own. Both properties are enforced inside
   `dig-mirror-coin`, not re-checked here. There is no supply-reducing path.
3. **By amount** (§25.3): per coin, exactly the margined per-epoch requirement; per pass, at most
   that amount times the number of held `(store, root)` pairs, plus fees.
4. **By fee source and size.** Fees are paid from XCH coins only — the crate's builders take
   separate fee inputs, so a fee can never shave collateral. `fee_mojos` per spend MUST come from a
   named constant, MUST be recorded in the audit entry, and MUST NOT exceed
   `MIRROR_SPEND_FEE_CEILING_MOJOS` = 1_000_000_000 (0.001 XCH). The ceiling MUST be enforced
   against the fee the spends THEMSELVES pay — `MirrorSpends::fee_mojos()`, recorded by the builder
   that baked it into the bundle — and MUST NOT be a separate argument to `sign`. A fee passed
   alongside the artifact bounds a caller's claim about the bundle rather than the bundle, which
   would make this the one of these four bounds that any caller could step around by passing a
   different number. The shipped default fee is 0; a
   zero-fee reclaim is explicitly supported by `dig_mirror_coin::reclaim`.

**The signer instance is module-private.** It is constructed at bring-up from the operator seed —
only when the seed opens under the device key (§16.4 `BootstrapState::Opened`/`Created`); a `Locked`
or `Orphaned` wallet yields no signer and the lifecycle reports itself unavailable rather than
degrading. The instance is NEVER installed on the general `WalletBackend`, is not reachable from any
RPC, control, or dapp method, and does not change `current_signer()`'s answer for any other surface.
Mirror spends do not transit `control.wallet.broadcast`, and `DIG_WALLET_ENABLE_LIVE_BROADCAST`
does not govern them: that flag gates the GENERAL node-custodied wallet surface, while this
lifecycle is governed by §25.7's switch and §23's audit contract.

**Mirror spends MUST be signed under CHIA MAINNET's `AGG_SIG_ME` domain.** A mirror coin is an
ordinary Chia L1 CAT, so the consensus that validates its spend appends Chia mainnet's genesis
challenge (`ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb`) to every `AGG_SIG_ME`
message. The `agg_sig_data` the operator wallet is opened with MUST therefore be
`MAINNET_CONSTANTS.genesis_challenge`, and MUST NOT be any `dig-constants` value: `dig-constants`
describes the **DIG L2** chain, and its genesis is the DIG PEER network id, not an L1 CAT's signing
domain. Signing under any other domain produces a valid signature over a message the network does
not check, so the bundle builds, signs and broadcasts and is then refused as
`BAD_AGGREGATE_SIGNATURE` by every peer, on every retry — with the collateral left locked and no
local error to see (dig-node#447).

**Key derivation MUST be the standard Chia HD derivation** from the operator mnemonic, so the phrase
exported by `dign wallet export-seed` (§16.3) recovers the collateral wallet — including anything
locked in unreclaimed mirror coins, via any standard wallet — with no dig-node code involved. The
owner key is the first derived key; its standard puzzle hash is the wallet's receive address, the
`owner_puzzle_hash` term of every hint this node creates, the address reclaims return to, and the
address create-change returns to. Deposits, bonds and reclaims therefore all move through ONE
address the wallet already tracks.

> **PARTIALLY PENDING.** THREE structural bounds of this subsection ARE satisfied by code: the
> spend-shape bound (`MirrorSpends`), the fee bound (read from the artifact, below), and the
> journal-taking signature, which makes one-record-per-signature and a derived intent properties of
> the call rather than of the caller. The sentence above — that the signer instance is *constructed at
> bring-up* from the operator seed — is NOT: `MirrorSigner::new` has no caller at this head, so no
> signer is constructed anywhere and the `Locked`/`Orphaned` reporting it describes does not exist.
> Nor is the audit-EXECUTION paragraph below satisfied: no entry is ever written for a mirror spend,
> no confirmation is observed, and nothing reconciles an `unresolved` or `failed` one. Both are
> tracked as <https://github.com/DIG-Network/dig-node/issues/412>.
>
> **A mirror spend is SENT only when the operator has enabled live broadcast.** The lifecycle
> builds its own `Broadcaster` on this node's ONE shared chain client, and it is built only when
> `DIG_WALLET_ENABLE_LIVE_BROADCAST` is on. On a default install — the flag defaults off — no
> broadcaster is constructed and no chain is dialed for one, so a planned reclaim refuses by name
> before it signs and no mirror spend reaches the mempool. The refusal is reported rather than
> silent, and the capability the node announces is derived from the SAME seam the money path is
> handed, so it cannot claim a power it does not have: `Available` holds exactly when a broadcaster
> is handed over.
>
> The broadcaster is built per pass rather than once at bring-up, because the shared client does not
> cache a failure — a node that started with no network broadcasts as soon as its network returns,
> and a node that cannot reach a chain reports that distinctly from a switched-off flag.
>
> Nothing is attached to the served `WalletBackend`: the broadcaster is scoped to the mirror
> lifecycle, signs only from the §16.4 operator wallet, and never acts on a user's behalf (§908).

**Every spend is audited, structurally — exactly ONE entry per signature, and it cannot lie about
the spend.** The signer takes the `SpendJournal` (§23.3) and opens the record itself, returning the
`RecordedSpend` for the caller to resolve: recording is the shape of the call. Two properties MUST
hold and are held here by construction rather than by convention. **One record MUST NOT be able to
back more than one signature** — an already-opened record passed by shared borrow can be reused in a
loop, accounting for N unattended spends as one. And **the intent MUST be DERIVED from the spends**,
never supplied alongside them: an intent a caller states can name a different amount, store or fee
than the bundle moves, and a record that is confidently wrong is worse than no record, because
§908's carve-out is bought precisely with the account being true. Entries carry
`kind: "mirror-coin"` (`spend_audit::kinds::MIRROR_COIN`),
`authority: { principal: "node", grant: "mirror-collateral" }`, the asset (`dig` for creates and
reclaims), the amount in DIG base units, the fee in XCH mojos, and `store_id`; `purpose` SHOULD name
the root and epoch. Confirmation is by observing the CREATED coin, never the funding coin (§23.2).
A pass that ends without an outcome leaves `unresolved`, and a `failed` entry at `broadcast` or
`confirmation` stage is reconciled against the chain, never treated as "the money stayed put" —
a mirror spend that landed unrecorded is collateral locked with the node believing it is not.

### 25.3. The amount is DERIVED per epoch, never a constant

The collateral per coin is `apply_safety_margin(required_per_store, margin_bp)` for the CURRENT
epoch, obtained through §24's requirement machinery (the censused epoch record) and the §24.4
margin. It MUST NOT be a compile-time constant, MUST NOT restate the model's arithmetic
(`required_per_store` is the whole answer; the formula as usually written omits the floor clamp),
and MUST NOT be read from a stale epoch. All lifecycle amounts are **DIG base units**
(`1 DIG = 1_000`); field and parameter names MUST say so — a mirror amount is never "mojos".

When the requirement is not `Known` (§24.2 — `not_censused`, `behind_finality_depth`,
`record_unreadable`, `no_chain_source`), **creates are DEFERRED** for that pass and reported with
the requirement's own reason. **Reclaims are unaffected**: a reclaim's amount is read from the coin
being reclaimed (`MirrorCoin::collateral()`), so recovering money never waits on a census. A coin
locked under a previous epoch's amount is reclaimed at that amount — reclaim returns what was
locked, exactly.

### 25.4. The reconcile pass — two observations, a pure plan, reclaims first

> **PARTIALLY PENDING — steps 3 to 6 are implemented; nothing supplies them and nothing schedules
> them.** The pure planner (`mirror/plan.rs`, `mirror/pass.rs`) and the pass runner
> (`mirror/runner.rs`) together satisfy step 3's table, step 4's reclaim-before-create order and
> never-gated-on-funds rule, step 5's clean stop at the affordable prefix, and step 6's in-flight
> suppression keyed on `(store, root, epoch)` from the audit record.
>
> **What is NOT implemented is everything that touches the world.** The two observations (steps 1–2)
> are a trait, `mirror::runner::MirrorEffects`, with no implementation; the confirmation record is
> not written; and the three triggers above — start-up, the `MIRROR_ROUND_LENGTH_MS` tick, and the
> debounced presence change — do not fire, because no pass is constructed. Tracked as
> <https://github.com/DIG-Network/dig-node/issues/412>. **Until that lands, a reader MUST NOT rely on
> any pass running at all**, and MUST read every clause below as describing what a pass WOULD do.

A pass runs: at start-up (once the wallet and a chain source are available), on every round tick
(`dig_constants::MIRROR_ROUND_LENGTH_MS`), and after a debounced presence change (§25.5). Each pass:

1. **Observes disk**: the `Held` capsule set (§25.1) — the desired bonds for the current epoch.
2. **Observes chain**: `dig_mirror_coin::list(source, owner_puzzle_hash)` — the coins actually owned.
3. **Plans**, purely (no I/O, no clock — the epoch is a parameter):

   | owned coin | its `.dig` held | action |
   |---|---|---|
   | `epoch == current` | yes | keep |
   | `epoch == current` | no | **reclaim** (`NoLongerHeld` — the penalised state; the priority) |
   | `epoch <  current` | either | **reclaim** (`EpochEnded` — the automatic form of the operation the legacy left to an operator; dig-node has no operator) |
   | `epoch >  current` | either | **keep** |

   The last row is a decision, not a gap: the epoch clock is wall-clock with no chain input
   (§24.3), so a slow local clock reads a legitimately-created next-epoch coin as "future", and
   reclaiming on that reading would destroy a valid bond on the strength of this machine's clock.
   Keeping is the recoverable direction; the coin becomes ordinary at the next tick. Duplicate
   coins for one `(store, root, epoch)` are ALL kept while the bond is held — choosing which valid
   bond to destroy is information the planner does not have — and both are reclaimed as
   `EpochEnded` after rollover.

4. **Executes reclaims FIRST, then creates.** Reclaims are NEVER gated on funds: they return
   collateral, which may fund the creates behind them, and a reclaim withheld for lack of funds is
   the legacy defect where a wallet at zero could neither advertise nor recover what it had locked.
   When no XCH is selectable, reclaims are attempted with `fee = 0`; zero-fee mempool admission is
   not guaranteed under fee pressure, so an unadmitted zero-fee reclaim is retried on subsequent
   passes rather than escalated. This is why epoch rollover is a re-create, not a top-up: pass
   order makes epoch n−1's returned collateral available to epoch n's creates.
5. **Creates in deterministic order** (sorted by `(store_id, root)`), stopping CLEANLY at the first
   unaffordable one: no partial spend, no retry loop, no half-written audit entry. The shortfall —
   which `(store, root)` pairs are uncollateralised and how many DIG base units short — is exposed
   on §25.8's surface. $DIG and XCH shortfalls are distinguished: $DIG missing blocks creates; XCH
   missing blocks fees, which degrades reclaims to `fee = 0` and blocks creates only if a non-zero
   create fee is configured. An underfunded pass MUST NOT stall, retry-loop, or block any other
   node work — the next pass re-derives everything, so added funds are picked up without restarting
   any epoch's work.
6. **Suppresses in-flight duplicates.** At most one in-flight create per `(store, root, epoch)`:
   a bond whose current-epoch create has a `pending` or `submitted` audit entry is excluded from
   the plan's create set until that entry resolves. The audit record is the in-flight ledger; the
   disk and the chain remain the only steady-state truths.

   **A funding-coin reservation is a BOUNDED hold.** The audit record also reserves the funding
   coins a non-terminal entry consumed, so a second create in the same confirmation window cannot
   re-select them. That reservation MUST expire: it holds a coin for
   `FUNDING_RESERVATION_WINDOW_MS` = `2 x MIRROR_ROUND_LENGTH_MS` (20 minutes) measured from the
   entry's LAST revision, after which the coin returns to the selectable set. An unbounded hold is a
   lockout — a spend that never lands would strand its inputs forever and a genuinely funded
   operator wallet would report `Insufficient` permanently. The window is derived: the chain-side
   figure is the wallet's own post-broadcast reservation lifetime (10 minutes, roughly a dozen Chia
   blocks), and one further round is added because this hold is re-evaluated only once per
   `MIRROR_ROUND_LENGTH_MS`, so a threshold equal to the poll interval would release an entry on the
   first pass at which its confirmation could even have been observed. A record whose `updated_ms`
   is in the FUTURE keeps its hold.

   **Expiry MUST NOT change the record.** The entry stays exactly the `submitted` or `unresolved` it
   was, and stays resolvable by step 7 and by §23.5's reconcile indefinitely. Releasing a coin is
   not a claim that the spend failed: `unresolved` means "this node signed and does not know what
   happened", which remains true afterwards. Writing a `failed` entry to settle the bookkeeping is
   forbidden, for the same reason a `confirmed` entry carries its height and coin id inside the
   variant.

7. **Resolves spends an EARLIER pass broadcast.** A mirror spend is broadcast in one pass and
   confirms during a later one, so the outcome MUST be recorded by an id-keyed resolution over the
   audit record rather than by the handle that opened it. Before the observation of step 2 is
   planned against, every mirror-coin entry that is `submitted` or `unresolved` is resolved as
   follows, and only as follows:

   | operation | its positive key | how the height is obtained |
   |---|---|---|
   | reclaim | the `intended_coin_id` the submission recorded | a coin read on that id |
   | create | the coin in step 2's observation matching `(store, root, epoch)` | a coin read on THAT coin's id |

   A create records no `intended_coin_id` — the created coin's parent is whichever funding input the
   builder drew from — so its key MUST be the coin's appearance in the chain observation. A coin id
   MUST NOT be derived, guessed, or otherwise invented for this purpose.

   The coin read has THREE outcomes and they MUST stay three: a height (resolve to `confirmed`); the
   coin absent, or present with no height (resolve nothing); the source unable to answer (resolve
   nothing, and NOT as an absence). A source that cannot be reached is not evidence about a coin in
   either direction.

   Disappearance MUST NOT be used as a key. The mirror puzzle hash is shared by every mirror coin,
   so a coin leaving the owned set proves only that SOMEONE spent it, and a short scan is
   indistinguishable from a spend.

   Where more than one open entry claims one coin — two reclaim attempts of the same coin derive the
   same child id, and step 6 deliberately does not suppress on `unresolved` — NONE of them is
   resolved. At most one of those bundles created the coin, and this node cannot tell which; the
   entries remain `unresolved`, which is what they are.

A confirmed create is `Confirmed { height, coin_id }` in the audit record, observed on the created
coin. The `intended_coin_id` is recorded at submission so §23.5's reconcile accounts for it.

### 25.5. Presence and debounce

> **PARTIALLY PENDING — the debounce rule is implemented and now has a caller; the scanning is
> not.** The stability-across-a-window rule, in both directions, is satisfied by the pure tracker in
> `mirror/presence.rs` and its `SETTLING_WINDOW_MS`, and `mirror::runner::PassRunner` debounces the
> advertisable half of every observation through it. **Nothing feeds THAT**: there is no periodic
> scan, no start-up scan, because `MirrorEffects::observe_disk` has no implementation. The WATCHER half is
> no longer pending: `mirror/events.rs` watches the capsule cache and accelerates the pass, bounded
> by the four rules below
> — so the scanning cadence described below, the un-debounced start-up exemption, and the claim that
> the periodic pass is the correctness mechanism are all still pending, tracked as
> <https://github.com/DIG-Network/dig-node/issues/412>.

Presence changes are detected by SCANNING, with an optional watcher as an accelerator — never the
reverse. A watcher event is exactly what a crash, an unmounted volume, or an uncovered path loses;
the periodic pass (§25.4) is the correctness mechanism.

The watcher is implemented (`mirror/events.rs`). It watches the capsule cache directory and MUST
obey all four of the following; a node whose watcher cannot be established, or whose events are all
dropped, MUST still converge on the round timer alone.

1. **An event MAY only lower the instant of the next pass, never raise it.** The round deadline is
   computed on entry to the wait and every return happens at or before it, so the timer is a
   backstop rather than a fallback. The round length MUST NOT be lengthened to compensate for having
   events.
2. **Events are COALESCED, never queued.** The pending state is one instant, so N events in a window
   — including events arriving while a pass is running or wedged — owe exactly ONE wake.
3. **An observing wake fires after `QUIET_PERIOD_MS` (5_000) of quiet**, and schedules exactly one
   **settling** wake `SETTLING_WINDOW_MS` later. That second wake MUST NOT re-arm, so a burst of any
   size causes at most two passes.
4. **No two event-driven passes are closer than `SETTLING_WINDOW_MS`.** A pass cannot act on a change
   the tracker has not yet seen hold for a window, so anything closer is amplification on a path that
   spends money.

**Chain events do NOT trigger a pass, and no mechanism exists by which they could.** Chain is
observed inside the pass, on the round timer. This is a limitation of the interfaces available, not
only a design preference, and the two are worth separating:

- **There is no chain event to subscribe to.** `MirrorEffects::observe_chain` reads through
  `ChainSource` (`dig-chainsource-interface`), whose entire surface is request/response —
  `coin_record`, `coin_records_by_puzzle_hash`, `coin_records_by_parent`, `coin_spend`. It exposes
  no subscription, no stream and no callback, so there is nothing for a waiting pass to select on.
  The node's own §14.2 chain-watch is likewise a POLL loop, not a push source.
- **The one push path in the node cannot say a mirror coin changed.** The wallet's direct-peer sync
  (§18.6) does hold a real `request_puzzle_state(subscribe = true)` subscription and publishes to
  the §18.14 `EventBus` — but `SyncEvent::CoinState` is fieldless. It names no coin, no puzzle hash
  and no height, and it reports the WALLET DB rather than the mirror's chain view. Waking a pass on
  it would wake a money-spending pass on any wallet coin activity whatsoever, with no evidence the
  event was relevant, at up to the `SETTLING_WINDOW_MS` floor rather than the round.

Independently of both, the two things a pass acts on are not chain-shaped: a CREATE is decided from
disk presence, which IS event-driven; and the epoch rollover a RECLAIM waits on is wall-clock.

What a chain event WOULD buy is freshness of the §25.8 observation — a mirror coin spent out from
under this node is reported up to one round late. That is a staleness bound on a read-only surface,
never a money-safety gap, and closing it needs a coin-state push carrying the coin it is about.
Tracked as <https://github.com/DIG-Network/dig-node/issues/482>.

The debounce is **presence-stable-for-a-window**, not a timer after an event: a bond must be
observed in the SAME state across `SETTLING_WINDOW_MS` (default 30_000) before that state is acted
on, in BOTH directions. An event-reset timer never settles under repeated rewrites and cannot see
changes that produced no event. A capsule that appears and vanishes inside the window was never
stable and triggers neither a create nor a reclaim — this is the churn control that prevents a
flapping file from costing two fees per flap, and it is why an atomic replace (delete-then-create
to a watcher) does not produce a spurious round trip.

Two exemptions: the START-UP scan is un-debounced — a scan at start-up IS the settled state; and
the node's own capsule writes are structurally invisible mid-write, because a capsule stages under
the downloads directory and is renamed into the inventory only after verification, so the scan
cannot observe a half-written file the node produced itself.

### 25.6. The DHT pointer, and epoch rollover

> **IMPLEMENTED.** The announce seam attaches the pointer
> (`dig_node_core::dht::announce_inventory_ids_with_pointers`), the rollover re-announce is
> `DhtHandle::reannounce_on_epoch_rollover`, and the node's production pointer source is
> `dig_node_service::mirror::pointers::SnapshotMirrorPointers`, which reads the observation the last
> pass published. A node with no observation, or with no coin for a capsule, publishes no pointer;
> that is an ordinary configuration and not a fault.

After a create confirms, the node attaches the coin id to its DHT provider record
(`dig_dht::ProviderRecord::unverified_mirror_coin_id`) for that content, and it MUST re-announce on
epoch rollover once the new epoch's coin confirms — dig-dht has no clock and republish re-attaches
whatever was recorded at announce time, so an un-refreshed pointer goes stale one epoch after
publication and a correctly-collateralised node reads as uncollateralised.

Only a coin bonding the CURRENT epoch may be published. A coin from a previous epoch advertises
nothing, and pointing at it makes a correctly-collateralised node read as uncollateralised — the
same failure the rollover re-announce exists to prevent, reached without any rollover. A whole-store
announce carries no pointer at all: a coin bonds one `(store, root, epoch)` tuple and cannot speak
for every generation of a store.

The pointer is an UNTRUSTED convenience (NC-12): it tells a verifier where to look, never what the
coin is. Its absence MUST NOT degrade discovery or be treated as a fault. A verifier — this node
when it checks others, and others when they check this node — accepts a coin as bonding
`(store, root, epoch)` only on the coin's own evidence: it sits at the mirror-coin puzzle hash, is
genuinely $DIG with the asset id re-derived from the creating spend, carries the declared
collateral, and `MirrorCoin::advertises(store, root, epoch)` passes — an exact equality on the
declared tuple plus a recomputed hint, which is what defeats the constructible additive-morph
collision (the epoch term is freely chosen, so hint equality alone proves nothing).

### 25.6a. Acting on another peer's claim

A node that LOCATES a holder verifies that holder's claimed bond and **promotes a proven one**. The
verdict has three states, which are never collapsed into two, but the ranking has exactly TWO tiers:

| verdict | established | ranking |
|---|---|---|
| bonded | the named coin passes every §25.6 check for this exact `(store, root, epoch)` AND declares the peer claiming it | promoted |
| unverified | no pointer was published, the chain could not answer, this node holds no censused requirement for the epoch, or the coin does not declare the claimant | baseline, position unchanged |
| unbonded | the chain answered and the claim is false | baseline, position unchanged |

**Ranking gives credit; it MUST NOT take credit away.** A provider record is hearsay — whoever
answers a lookup chooses every field of it, including a coin id it attributes to somebody else — so a
disproven pointer MUST NOT rank a holder below where no pointer at all would have put it. Otherwise
attaching a bogus coin id to an honest holder's record would be a demotion primitive available to any
stranger at no cost. Withholding credit has no such abuse: the most a liar achieves is the ranking
that would have existed had it said nothing.

**A coin id proves the bond, never the bearer.** A coin id is a public fact, so a coin that bonds the
content says nothing about WHO is offering it. Promotion therefore additionally requires the coin's
own owner-written declaration of the claiming `peer_id`, and a node that cannot read such a
declaration MUST NOT promote.

That declaration closes coin substitution — a stranger republishing another's coin id under its OWN
peer id earns nothing, because the coin does not name it. **It does NOT close address substitution,
and a node MUST NOT treat it as though it did.** A record may carry an honest holder's peer id, that
holder's real coin id, and the ATTACKER's addresses: the coin binds coin to `peer_id`, never `peer_id`
to an address, and a provider record's `peer_id`-to-address association is unauthenticated hearsay
that no chain read can settle. Such a record satisfies the declaration check and would be promoted on
the strength of somebody else's bond.

Closing that requires a separate restriction, which a node performing promotion MUST apply: promote
only from a record whose `peer_id`-to-address association is itself authoritative — a first-hand
announce from the peer being ranked, not a slate forwarded by a third party — or defer the credit
until the dialled identity has been checked against the claimed `peer_id`. A dialler is not by itself
a backstop, because peer ids are derived from the presented certificate rather than pinned against
the dialled identity; the residual an unrestricted implementation carries is traffic redirection, not
a stolen bond.

**One locate is bounded work.** The size of a located set is chosen by whoever answered the lookup,
so a node MUST bound the number of bonds it reads against a chain per locate, verifying in source
order and leaving the remainder at baseline.

**A `bonded` verdict MUST rest on AGREEMENT across independently drawn, concurrently-held untrusted
peers -- never on one source.** The §25.6 checks establish that a coin and its creating spend are
internally consistent; none of them establishes that the coin was ever on chain. A coin currying the
real, public $DIG CAT puzzle around an invented parent satisfies every one of them, so a verdict
taken from a single provider promotes a bond that does not exist, at no collateral cost to whoever
published it. The two reads that decide the verdict -- the coin record, and the spend that created
it -- MUST each be corroborated: below the corroboration floor, or on disagreement, the verdict is
`unverified` and MUST NOT be `bonded`. A node MUST NOT fall back to a single source when
corroboration is unavailable, because falling through to one endpoint exactly when the peers failed
to agree lets that endpoint overrule them.

The verification is performed in the ORDER §25.6 states, with one refinement that is normative: the
`advertises` binding is checked BEFORE the collateral magnitude. A node that has not censused the
epoch cannot price a bond, and checking magnitude first would make every verdict on such a node
`unverified` — including a holder pointing at a coin that plainly bonds a different store.

**A holder is never refused, dropped, or blocklisted on a verdict.** A chain outage, an epoch
rollover, a republished record carrying a pointer that has since gone stale, and a deliberate lie are
indistinguishable at the moment of reading, and only one of them is an attack; a node that refuses on
any of them converts its own partition into a rejection of honest peers. Promotion is the whole
remedy: a holder that proves its bond is served first, and every other holder keeps exactly the
standing its source gave it.

Absence of a pointer is the ORDINARY case and MUST cost no chain read at all. `unverified` for an
absent pointer is not a degraded answer — it is the honest state of a claim nobody looked at.

A verdict is cached only for the exact `(coin id, store, root, epoch, claiming peer id)` it answered.
Every component is load-bearing. One coin bonds one `(store, root, epoch)` tuple, so caching by coin
id alone would let a genuine bond answer for content the same coin does not bond — the substitution
`advertises` exists to refuse. And the verdict is peer-DEPENDENT: it is `bonded` only when the coin
declares the peer offering the record, so a key omitting the claiming peer id would serve one
holder's earned `bonded`, for the whole cache lifetime, to any stranger republishing the same
publicly-visible coin id — reinstating through the memo the substitution the ownership question
exists to refuse. The cache MUST also be probed under the node's TRUE current epoch rather than a
remembered one, or a probe taken after a rollover hits the entry stored under the previous epoch and
returns a verdict taken under the wrong one.

While the node has no sound source for the coin-to-peer binding, `bonded` is unreachable for every
input, and the verifier MUST then read no chain at all: the reads would be paid, at a third party, for
a verdict the credit-only ranking provably discards. That short-circuit MUST be conditioned on the
binding source itself, so that it lifts when the source arrives rather than needing a second switch
to be remembered.

Only DEFINITE verdicts are
cached: `unverified` records this node's own momentary inability to look, and holding it would keep
an outage in force after it had ended. The cache is keyed partly on attacker-chosen input, so it MUST
be bounded, and overflow MUST evict rather than clear — clearing would let a stranger discard every
verdict a node has earned by rotating coin ids.

### 25.7. Consent, the switch, and revocation

> **PARTIALLY PENDING.** The switch itself is real — it persists in `collateral.json`, defaults on,
> and the planner honours it by forcing the desired bond set empty so every live coin falls into the
> reclaim set. What does NOT exist at this head is the pass that acts on that plan, so **turning
> collateralisation off today reclaims nothing, because nothing is ever created either.** The
> revocation bullet below describes the behaviour once
> <https://github.com/DIG-Network/dig-node/issues/412> lands; it is decided, not performed.

There is deliberately no per-spend approval; the standing authority is the consent model, and it is
honest the same way auto-tipping (§18.23) is: **disclosed, default-on, bounded, fully audited, and
one setting to turn off** (§6.0/#207).

* **What the user accepts, and when:** running dig-node with collateralisation enabled (the
  default) and funding its operating wallet. The grant is named — every audit entry carries
  `grant: "mirror-collateral"` — and the account of every exercise of it is `dign spends` and the
  dig-app Activity tab.
* **The switch** is a persisted node setting (`collateral.json`, beside §24.4's margin; the node is
  the authoritative home §24.4). It gates CREATES ONLY. **Reclaims run regardless of the switch** —
  a disable that stopped reclaims would strand locked funds, which inverts the point of revoking.
* **Revocation reclaims what is locked, with no new machinery:** OFF forces the desired bond set
  empty, so the next pass reclaims every live coin this wallet owns (current epoch as
  `NoLongerHeld`, prior epochs as `EpochEnded`) and the collateral returns to the wallet balance.
  Per-store revocation is deleting/unpinning the `.dig`; the invariant does the rest.
* Disabling collateralisation does not touch the wallet, the audit record, or any other surface.

### 25.8. The per-store state surface

> **IMPLEMENTED.** The method `control.mirror.bondStates` is served, `dign mirror bond-states` is
> the verb (§8.6 CLI parity), and it now ANSWERS: the mirror pass observes on its own round timer
> and publishes what it saw, and this method serves that observation.
>
> The answer is a published SNAPSHOT rather than a read this call performs, and that is a security
> property rather than a cache. Observing per request would turn one token-gated call into an
> operator-seed unseal, a PBKDF2, up to `dig_mirror_coin::MAX_CANDIDATES` chain lookups and an
> oracle read — a real amplification surface, since a paired token is a much weaker predicate than
> "trusted". A node whose first pass has not yet completed answers
> `unknown { reason: "chain_unreadable" }`, which remains the honest answer and is never an empty
> page. A bond whose create is refused — for want of an advertised URL, for want of uncommitted
> operator $DIG, or because the chain could not be read — reports as uncovered, which is what it is.

The lifecycle exposes, per `(store, root)`, over the control plane and with a `dign` verb (§8.6
CLI parity): the bond state — `bonded { coin_id, epoch, amount }`, `pending` (in-flight create),
`unfunded { short_dig_base_units }`, `deferred { requirement reason }` (§25.3), `withheld`
(`Relayed` provenance — deliberately not advertised), `disabled` (the node-wide switch, §25.7),
`unadvertised` (that switch ON, but no entry in `DIG_MIRROR_ADVERTISE_URLS` is publishable, so this
node advertises nothing and a coin would bond nothing — §25.10), or
`reclaiming { coin_id, epoch, amount }` — so a client can distinguish "out of funds" from "withheld
on purpose" without guessing from the store list. Conflating those two produces hourly alarms about
a healthy node (dig-app#300). The method is declared in `dig-node-control-interface` (release-first)
before the node serves it.

**The mirror wallet is the node's OWN, and `control.wallet.operatorAddress` names it.** The wallet
that pays mirror collateral is the §16.4 machine-custody operator wallet, derived from the autoseed
— never the user's. Every figure in this section is about that wallet, and until it could be named
an operator reading `unfunded, short 1010` had no way to learn which wallet was short, nor where to
send money to fix it: one node reported exactly that while its operator's own wallet held 1,015,000
base units of $DIG, both statements true and each about a different wallet. The method answers
`{state:"known", address, puzzle_hash}` for this node's own wallet, or
`{state:"unavailable", reason}` — `not_initialized` for a node that has never run autoseed setup,
which is not a fault, and `unreadable` for one whose seed will not open, which is, and which also
means the node cannot pay collateral. It is TOKEN-GATED, because the caller does not name the
address and the node therefore volunteers its own node-to-address association; it is OWNED rather
than delegated, because forwarding it upstream would answer with another machine's wallet; and it
returns a DESTINATION only — no seed, key or derivation material, in any encoding. The
implementation reaches the address through `dig_wallet::operator_wallet::operator_address`, which is
built on `operator_puzzle_hash` and constructs no `WalletSigner` at all, so §908 holds by the types
rather than by discipline. The address is encoded with the wallet backend's own network prefix,
never a constant, so a node reading testnet coins cannot render a mainnet address beside them.

**`disabled` and `unadvertised` are both node-wide, and only ONE of them is a fault.** Both make every
row read the same token together and neither has a coin. They differ in whether the operator already
knows: `disabled` is that operator's own switch (§25.7) and MUST NOT be presented as a fault, while
`unadvertised` is the switch ON and the node silently unable to honour it because
`mirror::advertise::configured_urls` accepted no entry — the list is empty, or every entry was rejected
as non-absolute or reachable only from this machine, which is the same condition `MirrorEffects::create`
refuses every bond on (§25.10). The node MUST report `unadvertised` for that condition and MUST NOT
report it as `disabled`, which would oblige a conforming client to stay silent about the only reason
this node bonds nothing, nor as `unfunded`, which would name a figure and demand $DIG that would create
no coin.

The surface MUST hold four properties, each of which is a money statement:

* **The rows are the SERVED set — held AND relayed.** `withheld` is otherwise unreachable: a
  relayed capsule is by construction absent from the desired-bond set, so a producer keyed on the
  held set alone would answer "no such row" where this section promises "withheld on purpose", and
  would then claim `complete` over a set it had silently narrowed. A node that cannot determine
  provenance MUST answer `unknown { provenance_unknown }` for the WHOLE call.
* **Every per-row state is a DEFINITE statement.** A fact the node could not read makes the WHOLE
  answer `unknown` with the reason, never a degraded row and never an empty list: a truncated list
  and a complete one read identically. The one exception is not an exception — an unreadable WALLET
  is `deferred { balance_unreadable }`, which is definite ("this bond cannot be priced, because the
  balance could not be read") and MUST NOT be reported as `unfunded`, which asserts a shortfall the
  node has no evidence for.
* **`locked_dig_base_units` is the WHOLE-SET total, including coins being reclaimed**, and it is
  computed by the node. A client MUST NOT sum the page: a page sum under-reports locked money by a
  page boundary, and money reported as free while it is on chain is wrong in the reassuring
  direction. Reclaiming coins are included because their money is locked until the reclaim confirms.
* **The order is ascending over the canonical key**, a lowercase unprefixed 64-hex `(store_id,
  root)`. Keys are normalized BEFORE they are ordered, so a producer and a client cannot disagree
  about where a cursor points. A page states `complete` positively rather than by its length, a
  caller resumes from the `cursor` it was HANDED, and a malformed cursor or an out-of-range page
  size is REFUSED (`-32602`) rather than clamped or ignored — a silently dropped cursor restarts a
  walk while looking like it resumed.

### 25.9. Failure directions, stated

* A missed CREATE fails safe: money stays in the wallet, the node is undiscoverable for that root,
  and §25.8 says so.
* A missed RECLAIM fails expensive (the penalty) — which is why reclaims run first, why the
  start-up scan is the reliable path, and why `.dig`-gone is the highest-priority row of the plan.
* A slow clock KEEPS foreign-epoch coins (never destroys a valid bond); a fast clock creates the
  next epoch's coin early and reclaims the old one on the same pass — the same funds movement as
  an ordinary rollover.
* An unknown requirement defers creates and never defers reclaims.
* A crash at any point loses at most watcher events; the next pass re-derives the plan from disk
  and chain, and §23.5's reconcile plus in-flight suppression prevent both double-creates and
  silent losses.

### 25.10. What the node advertises, and why it is configured

A mirror coin publishes, in its memos, the URLs its store can be fetched from. `dig-mirror-coin`
requires at least one and imposes no other rule on them: they are advisory fetch hints, and the
crate's reader accepts any UTF-8 entry. This node therefore decides for itself what it is honest to
publish about itself.

The advertised URLs are **operator-configured and MUST NOT be derived**. A coin's URLs are fixed at
create for the whole epoch, so an address the node inferred about itself — a STUN reflexive address,
a resolver answer — may be unreachable from outside or may simply change, leaving collateral staked
on a claim the node cannot keep, which this section penalises. The operator sets them in
`DIG_MIRROR_ADVERTISE_URLS`, separated by commas or whitespace.

* The list MAY carry several entries; the memo layout is built for that. IPv6 entries SHOULD be
  listed first, and the node publishes the operator's order verbatim rather than sorting it.
* An entry MUST be an absolute URL with a scheme and a host. No scheme allowlist is imposed.
* An entry whose host can only mean this machine — loopback, the unspecified address, link-local,
  `localhost`, or `dig.local` — MUST NOT be published. The rule is on the address the host DENOTES,
  not on how it is written: it MUST hold under every scheme, including a non-special one whose host
  is opaque, and an IPv6 address that embeds an IPv4 one MUST be judged by the address it embeds.
  A private or LAN address MAY be published: it is a deliberate operator choice and risks only that
  operator's own stake.
* A rejected entry is dropped with a warning naming the reason; the surviving entries are published.
* When no entry survives, **the node advertises nothing and creates no mirror coin**. That refusal
  is the correct default: publishing a URL nobody can fetch from is worse than publishing none,
  because it locks collateral against a claim that will be penalised.

Changing the value affects only coins created after the change. Bringing an existing coin into line
means reclaiming and re-creating it — a round trip and a fee — and the node MUST NOT reclaim in
response to a configuration edit.


### 25.11. Funding a create — authentication precedes every figure the operator is told

The $DIG that funds a create is selected from ONE address: `dig_cat_puzzle_hash(owner)`, the CAT
curry of the operator's own puzzle hash. That address is **publicly derivable** — the owner puzzle
hash is public and the curry is canonical — and anyone may pay any coin to any puzzle hash. So a row
returned by the scan is a CANDIDATE, never a coin, and the number and declared amounts of those rows
are chosen by whoever last paid into the address.

A candidate becomes one of this operator's coins only by AUTHENTICATION: its creating spend is read
from chain and executed, and a CAT child matching the candidate is produced, of the $DIG asset and
at this operator's puzzle hash. The node MUST NOT treat an unauthenticated candidate as money.

**The node MUST authenticate before it computes any figure it reports.** In particular:

* The spendable total in a shortfall MUST be the total of AUTHENTICATED candidates. It MUST NOT be
  the address total. An understated total sends an operator to buy $DIG they already hold, and the
  §25.12 gate then suppresses the correction as immaterial.
* The input bound MUST be applied to a selection drawn from AUTHENTICATED candidates only. Applied
  to the raw scan it is a bound a stranger sets, and the refusal it produces is the operator-facing
  claim *the wallet holds enough $DIG, in too many pieces* — so a stranger paying enough small coins
  into the address chooses which of two OPPOSITE instructions the operator is given, and an operator
  holding nothing is told that adding more will not help.
* A candidate that fails authentication MUST be passed over rather than aborting the selection, MUST
  be counted and reported, and MUST NOT occupy an input slot.

**Authentication costs one chain read per candidate, so it MUST be bounded by a constant** that does
not depend on how many candidates exist. Without such a bound the reads one automated pass performs
are chosen by whoever paid coins into the address, on the pass timer, indefinitely.

**A walk truncated by that bound leaves the wallet UNMEASURED.** The node MUST refuse with a
condition of its own that states NO total — it MUST NOT report the total of the candidates that
happened to be walked, and MUST NOT clear a live shortfall. It MUST classify as §25.12's
*unmeasured*, and MUST therefore be reported to the operator without an amount: an operator whose
node has stopped bonding because a stranger filled the scan address is otherwise never told
anything, on any pass, indefinitely.

**A pass that authenticated no candidate at all has no spendable total either.** The commonest such
pass is one that priced a create and could afford none, so the selection was never invoked. It is
still SHORT — authentication only ever removes candidates, so a reported balance below one create's
cost proves the authenticated one is below it too — but the SIZE of the gap is not established, and
the node MUST NOT quote the address total, or any figure derived from it, as the spendable one. It
MUST classify as §25.12's *unmeasured*.

### 25.12. Reporting a funding shortfall to the operator

The node MUST distinguish four funding observations per pass — *healthy*, *short* (with the amount
and the remedy), *unmeasured* (blocked, with no amount), and *unknown* — and MUST raise an
operator-facing message only on a CHANGE: once on entering the short state, again only when the
remedy changes or the deficit grows materially, and once on recovery. An *unknown* observation MUST
raise nothing and MUST NOT clear a live shortfall.

An *unmeasured* observation MUST raise a message once on entering it, MUST state NO spendable total
and NO deficit, and MUST NOT clear a live shortfall. Saying nothing about the AMOUNT and saying
nothing AT ALL are different: the second leaves a node that has silently stopped bonding
unreported, and leaves a shortfall already alerted on latched at a figure that can never be
corrected. The message MUST name the condition and an action the operator can take, and MUST NOT
assert a remedy the observation does not establish — in particular a truncated walk MUST NOT tell
an operator to add $DIG, since adding it need not help.

A *short* observation's spendable total MUST be authenticated (§25.11). A pass that has no
authenticated total is *unmeasured*, never *short with the address total*.

**A pass that planned no create because it could afford none is SHORT, not healthy.** The two
conditions that produce an empty create list are opposites — nothing to bond, and nothing
affordable — and only the first is healthy. Classifying the second as healthy leaves the shortfall
with no producer for the commonest real case (a wallet holding less than one create's collateral,
which never attempts a create and so never produces a funding refusal), and worse, CLEARS a live
shortfall and announces a recovery that has not happened.

The figures a shortfall reports MUST be the money that must actually be ADDED: the authenticated
$DIG remaining after the affordable creates were funded, against the cost of those that were not.
The wallet balance alone overstates what is available towards the unmade creates, and an
unauthenticated balance is in addition a figure a stranger chooses (§25.11) — so where the
remaining $DIG has not been authenticated, the cost of the unmade creates is reported alone, as an
*unmeasured* observation.
