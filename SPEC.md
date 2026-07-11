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
interface defined in the `dig-rpc-types` crate and specified on the docs.dig.net Protocol pages.
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
  (`dig-nat`/`dig-gossip`/`dig-dht`/`dig-pex`/`dig-download`/`dig-peer-selector`/`dig-protocol`)
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
- the **blind-passthrough relay** to the upstream DIG RPC for methods the node does not
  resolve (§5.4);
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

1.4. **Canonical RPC interface — `dig-rpc-types` + `dig-rpc`.** The RPC surface this node exposes
(method names + request/response types, the error-code taxonomy, and the tier classification) is
the canonical DIG-node RPC interface defined ONCE in the **`dig-rpc-types`** crate
(`modules/crates/dig-rpc-types`) — the single source of truth this node (the one implementation
shared by both host shells) and the `rpc.dig.net` gateway share, so the two can never drift. The
JSON-RPC server framework (transport surfaces, tier allowlist enforcement, rate limiting, mTLS) is
the **`dig-rpc`** crate (`modules/crates/dig-rpc`), which depends only on `dig-rpc-types`. This
SPEC's method catalogue (§5.5), envelope rules (§5.1), and error catalogue (§10) MUST match
`dig-rpc-types` exactly; where they differ, `dig-rpc-types` is authoritative and this SPEC is the
drift to fix. The OpenRPC document (§6.3) is generated from `dig-rpc-types`' own
method/tier/error tables. (Full type-level adoption of `dig-rpc-types`/`dig-rpc` in this repo's
code is a tracked follow-up — see §1.5; this SPEC records the contract they define, which the
node's dispatch already conforms to byte-for-byte via the conformance vectors.)

1.5. **dig-rpc / dig-rpc-types adoption status.** `dig-rpc-types` is a PRIVATE sibling repo and
`dig-rpc` depends on it; this public repo's CI cannot fetch it without authenticated private-repo
access. The node therefore currently mirrors the canonical contract (the control-plane error
codes `-32030`/`-32031`/`-32032` and machine strings, the method set, the chunk object) as
byte-identical constants + types rather than importing the crates, with the shared values asserted
against the conformance vectors. Swapping to a direct `dig-rpc-types` type dependency + the
`dig-rpc` server framework is a tracked follow-up gated on the private-repo CI-auth wiring (the
`dig-rpc` repo itself already authenticates its `dig-rpc-types` sibling checkout). Until then the
wire is guaranteed identical by the conformance vectors, not by a shared crate.

---

## 2. Identity and naming

2.1. **Canonical name.** The produced binary, the service-shell Cargo package (`dig-node-service`),
the OS service, and every machine-readable service-identity surface are named `dig-node`. The node
ENGINE library crate is `dig-node-core` (lib `dig_node_core`) — a distinct name from the `dig-node`
binary so the two are never confused (#216). Every machine-readable surface (`/health.service`,
`/version.service`, the CLI `--json` envelopes' `service` field) MUST report the service identity
string `"dig-node"` (`meta::SERVICE_NAME`).

2.2. **Node library version.** The node is the first-party `dig-node-core` engine library crate in
this workspace. The constant `meta::DIG_NODE_VERSION` MUST equal the node library's crate version
(`dig_node_core::NODE_VERSION`, its `CARGO_PKG_VERSION`) and is surfaced in `/version`,
`/.well-known/dig-node.json`, and `control.status` as `dig_node_version`. When the node library
version changes, or when the digstore store-format git dependencies (`digstore-*`) are bumped to a
new rev, the method catalogue MUST be re-verified against the node's real dispatch (the drift
guard, §5.6, enforces this).

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
| `DIG_NODE_HOST` | EXPLICIT localhost-listener bind IP override | *(unset)* | Parsed as `IpAddr`; unparsable/blank/unset ⇒ unset (§4.1's dual-stack default — see below), NOT a hardcoded `127.0.0.1` default. Setting it REPLACES the dual-stack default with exactly that one address (#288). |
| `DIG_RPC_UPSTREAM` | upstream DIG RPC base URL for passthrough + miss-proxy | `https://rpc.dig.net` | Normalized (§3.3); highest precedence (§3.4). |
| `DIG_NODE_CACHE` | explicit on-disk `.dig` cache dir | *(unset)* | Blank/whitespace ⇒ unset. Unset ⇒ shared canonical default (§3.5). |
| `DIG_NODE_DIGLOCAL` | toggle for the bare-`http://dig.local` listener | `true` | Falsy = `0`/`false`/`no`/`off`; truthy = `1`/`true`/`yes`/`on`; case/whitespace-insensitive; unset or unrecognized ⇒ **default true**. |

The default port is the UNCOMMON high port **`9778`** (not `80`/`8080`). Port 80 requires elevation
on most OSes, and both `80` and `8080` are the collision-prone common-dev ports most likely already
bound on a developer machine; `9778` is deliberately clear of the common-dev set
(80/443/3000/5000/8000/8080/8888/9000) and well-known service ports. It is the sibling of the
dig-wallet HTTP API's `9777` (wallet `9777`, node `9778`) and matches the local-node port the
digstore §5.3 resolver already expects (`DEFAULT_LOCAL_NODE_PORT`). Every consumer of the §5.3
`localhost` tier — the DIG Chrome extension's `server.host` default, the dig-installer, and the DIG
Browser — MUST target `localhost:9778` to match. `DIG_NODE_PORT` overrides it; the `http://dig.local`
listener (`127.0.0.2:80`) is unaffected — only this localhost port changed (#132).

The variables above are the shell's public bind/upstream/cache knobs. The node ENGINE library
(`dig-node-core`) additionally reads the following variables directly from the environment; the shell
does not own them (except `DIG_NODE_UPSTREAM`, which the shell SETS — see below):

| Variable | Meaning | Default | Rules |
|---|---|---|---|
| `DIG_NODE_CACHE_CAP` | LRU cache size cap, in bytes | `1073741824` (1 GiB) | Parsed as `u64`. Consulted ONLY when the persisted `cache_cap_bytes` key in `config.json` is absent or `0` (the persisted value wins). Unparsable/unset ⇒ default. |
| `DIG_NODE_COINSET` | override the coinset API base used for chain-anchored-root resolution | `https://api.coinset.org` (mainnet) | Blank/unset ⇒ mainnet default. Used for tests / alternate endpoints. |
| `DIG_NODE_PIN` | read-path anchored-root pin enforcement (§14.4) | `on` (ENFORCED, fail-closed) | ONLY `off`/`0`/`false` disable the node-side pin (a named offline/local-dev escape hatch); any other value or unset ENFORCES. Clients still verify proofs against their own trust root regardless. |
| `DIG_NODE_WATCH_INTERVAL` | chain-watch poll interval, in seconds (§14.2) | `30` | Parsed as `u64`; `0`/unparsable/unset ⇒ default `30`; floored at `1` s so a mis-set value cannot flood coinset. |
| `DIG_NODE_UPSTREAM` | **INTERNAL** — the effective upstream the node library reads | `https://rpc.dig.net/` | NOT a user knob. The shell resolves the upstream (§3.4) and writes this via `Config::apply_to_env()` (§3.5); the shell's public knob is `DIG_RPC_UPSTREAM`. |
| `DIG_WALLET_WC_PROJECT_ID` | initial/default WalletConnect projectId for the wallet host (§16) | *(unset ⇒ none)* | A persisted `wc_project_id` in `config.json` wins over this; a blank persisted value falls through to this env. Blank ⇒ treated as unset. |
| `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC` | outgoing-bandwidth throttle cap, in bytes/second (§17) | `0` (UNLIMITED — opt-in) | Parsed as `u64`; `0`, unparsable, or unset ⇒ unlimited (the throttle is a no-op until an operator configures a cap). Resolved ONCE at node construction. |

The peer-network layer additionally honors `DIG_PEER_NETWORK` (set to a falsy value to disable the L7
peer network) and `DIG_RELAY_URL` (override or disable the relay), which gate the P2P bring-up.

### 3.3. Upstream normalization

`normalize_upstream` MUST: trim whitespace, strip all trailing `/`, and prefix `https://` when the
value has no `http://`/`https://` scheme. An empty result is treated as unset.

### 3.4. Upstream precedence

The effective upstream is resolved in this order (first non-empty wins):

1. `DIG_RPC_UPSTREAM` env var — a deploy/CI override MUST never be silently overridden by a saved
   setting;
2. the persisted `upstream_override` key in `config.json` (written by
   `control.config.setUpstream`, §7.5);
3. the default `https://rpc.dig.net`.

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
3. **`127.0.0.2:80`** — the bare-`http://dig.local` listener (constants `DIG_LOCAL_IP` =
   `127.0.0.2`, `DIG_LOCAL_PORT` = `80`, `DIG_LOCAL_HOST` = `dig.local`). This bind is
   **best-effort**: on failure (no privilege, port in use, missing macOS `127.0.0.2` loopback
   alias) the node MUST log a structured warning to stderr and continue serving localhost-only —
   it MUST NOT abort. Skipped entirely when `DIG_NODE_DIGLOCAL` is falsy.

The distinct loopback IP `.2` exists so the port-80 bind can never collide with an unrelated
`localhost:80` service. The dig-installer writes the hosts entry `127.0.0.2  dig.local`; this
listener is what makes the portless `http://dig.local` URL reach the node. No listener may
bind `0.0.0.0` or the IPv6 wildcard `[::]` — the node is a localhost endpoint and MUST never be
LAN-exposed. A service install (§9) forwards `DIG_NODE_HOST` into the installed service's
environment ONLY when the operator gave an explicit override, so a plain `dig-node install` with
no override yields a service that also dual-binds by default, rather than freezing an IPv4-only
default into every future install.

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

The CORS layer reflects only **local origins**: `chrome-extension://*` and `http://<host>[:port]`
where `<host>` passes the §4.2 allowlist. `https://` and other schemes MUST NOT be reflected.
Allowed methods: `GET`, `POST`, `OPTIONS`. Allowed request headers: `Content-Type` and
`X-Dig-Control-Token`.

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
validates the `Origin` header itself, with the SAME allowlist §4.3's CORS layer reflects
(`chrome-extension://*` and an allowed local `http://` origin). A disallowed `Origin` MUST be
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
   root that is not the tip, an unconfirmable store, or an unreachable chain fails closed;
3. fetches the resource's ciphertext + inclusion proof + chunk lengths LOCAL-FIRST, then peer, then the
   public RPC (§4.6 cache order below);
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

**Local-first store cache (#290).** Resolution order per `(store, root)`:
1. a synced+verified `.dig` module on disk → serve LOCAL, no network (the DEFAULT once cached);
2. not held → serve the immediate resource from a peer / the public RPC AND trigger a single-flight
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

---

## 5. JSON-RPC surface (read plane)

The method catalogue (§5.5), request/response types, tier classification, and error taxonomy (§10)
below are the canonical set defined in the **`dig-rpc-types`** crate (§1.4) — the single source of
truth shared with `rpc.dig.net`. This node MUST NOT diverge from it.

### 5.1. Envelope rules

- `POST /` accepts a **single JSON-RPC 2.0 request object**. A non-object body (including a batch
  array) MUST be answered in-band with HTTP 200 and an `INVALID_REQUEST` (`-32600`) error envelope
  — never a transport-level failure.
- All JSON-RPC responses (success and error) are returned with HTTP **200**. The error taxonomy
  lives in the JSON-RPC `error` object (§10), not in HTTP status codes (the sole exception is the
  421 Host rejection, §4.2).
- Error envelopes minted by the shell MUST carry the numeric JSON-RPC `code` plus
  `data.code` (stable UPPER_SNAKE symbolic name) and `data.origin` (§10). Agents branch on the
  symbolic name, never on message prose.
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

Applied ONLY to content/proof methods (`dig.getContent`, `dig.getCapsule`, `dig.getProof`) and
only when the canonical field is absent — an explicit value MUST never be overwritten:

- `storeId` → `store_id`;
- `resource_key` / `resourceKey` → `retrieval_key`.

A `"latest"` or non-64-hex `root` is passed through untouched: the read path treats it as rootless
and proxies, which is correct for this shell (it performs no chain resolution of "latest").
Requests for all other methods MUST pass through byte-unchanged.

### 5.4. Blind-passthrough relay

When the read path answers `-32601`, the shell MUST POST the client's ORIGINAL request verbatim
(JSON body) to the configured upstream and return the upstream's parsed JSON envelope unmodified.
The shell is a transparent proxy for these methods: it MUST NOT rewrite params, results, or
upstream error codes. If the upstream is unreachable or returns non-JSON, the shell mints
`UPSTREAM_ERROR` (`-32010`). The relay client identifies itself with the User-Agent
`dig-node/<version>`.

### 5.5. Method catalogue

`meta::methods()` is the single source of truth for the method catalogue; `rpc.discover`,
`/health.methods`, `/openrpc.json`, and `/.well-known/dig-node.json` are all generated from it and
MUST NOT re-declare method names. Each entry carries a `served` class and `requires_auth` flag:

| `served` | Meaning |
|---|---|
| `local` | Resolved by the node library (`handle_rpc`). |
| `passthrough` | Read path returns `-32601`; relayed verbatim to the upstream. |
| `shell` | Answered by this service itself (`rpc.discover`). |
| `control` | The gated control plane (§7); always `requires_auth: true`. |

For the current node library (§2.2) the catalogue is:

- **local**: `dig.getContent`, `dig.getAnchoredRoot`, `dig.getManifest`, `dig.stage`,
  `dig.getCollection`, `dig.listCollectionItems`, the L7 peer surface (`dig.getNetworkInfo`,
  `dig.getPeers`, `dig.announce`, `dig.getAvailability`, `dig.listInventory`, `dig.fetchRange`),
  and all `cache.*` (`cache.getConfig`, `cache.setCapBytes`, `cache.clear`, `cache.listCached`,
  `cache.removeCached`, `cache.fetchAndCache`).
- **passthrough**: `dig.getCapsule` (an alias the node does NOT resolve — local-first callers use
  `dig.getContent`), `dig.getProof`, `dig.listCapsules`.
- **shell**: `rpc.discover`.
- **control**: the operator `control.*` methods of §7.4, plus the node-owned control methods the
  shell delegates to the node (`control.peerStatus`, `control.subscribe`, `control.unsubscribe`,
  `control.listSubscriptions`).

Param/result schemas for the `dig.*`/`cache.*` methods are owned by the digstore dig RPC and
published on docs.dig.net (Protocol → the L7 read/RPC pages); this repo's OpenRPC document is a
method + error **discovery** catalogue with intentionally permissive schemas.

Every non-`control.*` method MUST have `requires_auth: false`; every `control.*` method MUST have
`served: "control"` and `requires_auth: true`.

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
  `RESOURCE_NOT_AVAILABLE_AT_ROOT`/unavailable code `dig.fetchRange` reports on a miss) — distinct
  from the "held but no manifest" case above.
- Malformed `store_id`/`root` (not 64-hex) → `-32602` before any filesystem access.

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
{ dir, cap_bytes, used_bytes, shared }, methods: [names…] }`. The fields `status`, `version`,
`mode`, `upstream`, `cache` are the stable probe contract (the v0.2 server's health shape);
additions MUST be additive. `cache.shared` reports whether the effective cache dir is the shared
canonical one (`true`) or a process-private fallback (`false`), from the read path's resolver.

### 6.2. `GET /version`

Returns `{ service, version, commit, dig_node_version, protocol }` (§2).

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
token is NOT accepted for them.

### 7.3. The control token

- File: `<config_dir>/control-token`, where `<config_dir>` is the parent of the read path's
  `config.json`.
- Value: 32 bytes of OS randomness rendered as 64 lowercase hex characters. Generated at first
  run; subsequent runs (and other same-host processes) read the same value. On Unix the file MUST
  be written with owner-only permissions (`0600`, best-effort). The token MUST never be committed
  or logged.
- Presentation, either of (header preferred): the `X-Dig-Control-Token` request header, or the
  `params._control_token` field. Blank presentations are treated as absent.
- If the token cannot be persisted (unwritable config dir), the node MUST fall back to an
  in-memory token that no controller can read — the control plane fails **closed**; the read plane
  is unaffected.
- Randomness source: the kernel CSPRNG (`/dev/urandom`) on Unix; elsewhere a non-deterministic
  mixed fallback. The security model is *possession of a same-host-readable file*, layered on the
  loopback bind — not secrecy from a network attacker.

### 7.4. Control methods

All results/errors use the standard envelopes of §5.1. `storeId` and `rootHash` are canonical
lowercase 64-hex; a capsule reference is `storeId:rootHash`. Malformed refs yield
`INVALID_PARAMS`; runtime failures yield `CONTROL_ERROR`; capability absences yield
`NOT_SUPPORTED`.

| Method | Params | Result (essentials) |
|---|---|---|
| `control.status` | — | `running`, `service`, `version`, `commit`, `dig_node_version`, `protocol`, `uptime_secs`, `addr`, `upstream`, `cache`, `hosted_store_count`, `cached_capsule_count`, `pinned_store_count`, `sync.available` |
| `control.config.get` | — | `addr`, `port`, `upstream`, `upstream_override`, `cache_dir`, `cache_shared`, `config_path`, `sync_available` |
| `control.config.setUpstream` | `upstream` (URL string; blank clears) | `upstream` (normalized), `requires_restart: true` — persisted, effective on next start (§3.4) |
| `control.cache.get` | — | `cap_bytes`, `used_bytes`, `dir`, `shared` |
| `control.cache.setCap` | `cap_bytes` (number) | `cap_bytes` (floored at 64 MiB) |
| `control.cache.clear` | — | `cleared: true` |
| `control.hostedStores.list` | — | `stores[]`: `store_id`, `pinned`, `capsule_count`, `total_bytes`, `capsules[]` (capsule, root, size_bytes, last_used_unix_ms) — cached stores ∪ pinned stores |
| `control.hostedStores.pin` | `store` = `storeId[:rootHash]` | `store_id`, `root`, `pinned: true`, `fetch` = `{status: cached\|failed\|skipped, …}` (pre-fetch attempted only with a concrete root AND sync available; a skipped fetch reports `reason`) |
| `control.hostedStores.unpin` | `store` = `storeId[:rootHash]` | `store_id`, `unpinned` (whether a pin was removed), `evicted_capsules` — MUST evict every cached capsule of the store |
| `control.hostedStores.status` | `store` = `storeId[:rootHash]` | `store_id`, `pinned`, `capsule_count`, `total_bytes`, `capsules[]` |
| `control.sync.status` | — | `available`, `method: "section-21-whole-store-sync"`, `pinned_total`, `pinned_synced`, `whole_store_trigger_supported` (`false` at this pin — per-capsule sync only) |
| `control.sync.trigger` | `store` = `storeId:rootHash` (root REQUIRED), or `store_id` + `root` | `status: "synced"`, `size_bytes`, `served_root`; `NOT_SUPPORTED` when no §21 identity is loaded |

### 7.5. Ownership boundary

Cache and sync operations MUST proxy to the node library
(`cache_list_cached`/`cache_remove_cached`/`cache_fetch_and_cache`/`clear_cache`/
`set_cache_cap_bytes`/`cache_cap_bytes`/`cache_used_bytes`); the shell never duplicates read/cache
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
  `control.*` methods require the control token from `<config_dir>/control-token` (§7.3). Only a
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
token-gated test is read from `<config_dir>/control-token` after startup.

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
`dig-rpc-types` crate (§1.4/§1.5) — until it is wired in, this SPEC is authoritative.

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

- **`cache.setCapBytes { cap_bytes }` — the RESERVED cap.** Sets the reserved disk space for cached
  content, **floored at 64 MiB** (a `cap_bytes` below the floor is raised to it), and returns the
  applied `{ cap_bytes }`. `cache.getConfig` returns the live `{ cap_bytes, used_bytes, cache_dir,
  shared }`.

- **`cache.stats` — session cache telemetry (new).** Result:
  `{ cap_bytes, used_bytes, entry_count, total_bytes, evicted_count, evicted_bytes,
  content_cache: { hits, misses } }`. `entry_count`/`total_bytes` are the count and summed on-disk
  size of cached capsules; `evicted_count`/`evicted_bytes` are the disk-cache LRU evictions since the
  node started; `content_cache.hits`/`misses` are the decoded-content (RAM) cache lookups since
  start. All counters are process-lifetime (reset each start), never persisted.

### 7.11. Control-token pairing for browser controllers (#280)

An MV3 browser extension cannot read the `<config_dir>/control-token` file, so it cannot drive
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
  fresh 64-hex scoped token, PERSISTS it to `<config_dir>/paired-tokens.json` (owner-only, atomic),
  and marks the pending entry approved so the requester's next `pairing.poll` returns it. Approval is
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

**Paired-token store.** `<config_dir>/paired-tokens.json` = `{ "tokens": [{ id, token, client_name,
created_ms }] }`, owner-only, atomic writes. The auth gate accepts the master token OR any token in
this store (except for the pairing-administration methods).

---

## 8. CLI contract

### 8.1. Subcommands

`run` (default when no subcommand; serves in the foreground and is the unix-service entrypoint) ·
`run-service` (hidden; the Windows SCM entrypoint, §9.4; behaves as `run` off Windows) ·
`install` · `uninstall` · `start` · `stop` · `status`.

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

I/O-error mapping: `PermissionDenied` → 3; `AddrInUse`/`AddrNotAvailable` → 5; anything else → 6.
Numeric values and symbolic names are a stable contract and MUST NOT be renumbered.

---

## 9. OS-service contract

9.1. **Install levels.** Linux (systemd) and macOS (launchd) install at **user level** (no
root/sudo; runs as the installing user). Windows SCM has no per-user services, so install is
**system-level only**, and `install`/`uninstall` MUST fail fast with a clear
`PERMISSION_DENIED` when the console is not elevated (probed up front, not deep inside `sc.exe`).

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

9.3. **Entrypoint per platform.** The installed service runs `dig-node run-service` on Windows and
`dig-node run` on systemd/launchd (which exec the foreground process directly).

9.4. **Windows SCM protocol.** `run-service` MUST connect to the SCM via
`StartServiceCtrlDispatcher` under the exact §2.4 label, register a control handler, report
`Running` (accepting `Stop`) promptly — otherwise the SCM kills the process with error 1053 —
serve until the SCM `Stop` control, drive the same graceful shutdown as a signal, and finally
report `Stopped` (Win32 exit 0 on success, 1 on error).

9.5. **Graceful shutdown.** In the foreground, the serve loop MUST stop gracefully on Ctrl-C (all
platforms) or SIGTERM (unix — how systemd/launchd stop the service). One shutdown event MUST fan
out to both listeners (§4.1).

9.6. **Uninstall.** `uninstall` performs a best-effort `stop` first, then removes the registration.

---

## 10. Error-code catalogue (JSON-RPC wire)

Stable contract: numeric codes, symbolic names, and origins MUST NOT be renumbered or repurposed;
additions are allowed. This catalogue is the canonical set from **`dig-rpc-types`** (§1.4) — it
MUST match that crate exactly. `origin` distinguishes who minted the error: `shell` (this service),
`node` (the node library), `upstream` (relayed from the upstream DIG RPC), `boundary` (the
method-not-found cue).

**Canonical control-code assignment.** The control-plane errors are `-32030`/`-32031`/`-32032`.
`-32020`/`-32021`/`-32022` are RESERVED for onion-routing errors (`onion_circuit_unavailable` /
`privacy_requires_local_node` / `onion_hops_out_of_range`) — the published normative contract on
docs.dig.net — and MUST NOT be used for control. (`dig-rpc-types` is the source of this resolution;
any client that branched on the old control numbers keys on the symbolic `data.code`, not the
number.)

| Code | Name | Origin | Meaning |
|---|---|---|---|
| -32700 | `PARSE_ERROR` | shell | Request body was not valid JSON. |
| -32600 | `INVALID_REQUEST` | shell | Not a single JSON-RPC object (batch arrays unsupported); also the 421 Host-rejection body. |
| -32601 | `METHOD_NOT_FOUND` | boundary | Not resolved locally or by the upstream (internally: the passthrough cue). |
| -32602 | `INVALID_PARAMS` | node | Invalid/missing method parameters (also minted by the control plane for bad control params). |
| -32000 | `DISPATCH_FAILED` | shell | The shell failed to dispatch the request to the read path. |
| -32004 | `RESOURCE_NOT_AVAILABLE_AT_ROOT` | upstream | Genuine content miss at the requested root (relayed); distinct from transport failure. Also minted directly by the node library for a LOCAL miss at this same root — `dig.fetchRange` ("resource not held") and `dig.getManifest` ("capsule not held locally") — never a fabricated result. |
| -32005 | `ROOT_NOT_ANCHORED` | node | The node's mandatory read-path anchored-root pin (§14.4) fails closed: the requested root does not match the chain-anchored tip, the store has no confirmed on-chain generation, the chain is unreachable, or a rootless request cannot be resolved under enforcement. Minted by the node library on `dig.getContent`. |
| -32008 | `CONTENT_REDIRECT` | node | The node does not (or, under §17's throttle, will not right now) serve the requested content itself, but the DHT located peer(s) that hold it — `error.data.redirect` names them (`content`, `providers[].peer_id`/`addresses`, `redirect_depth`, `max_redirects`) so the caller re-requests there. Minted on a content miss (`dig.getContent`/`dig.fetchRange`/the peer range-stream) and on outgoing-bandwidth saturation (§17), bounded by the same redirect-hop cap either way. |
| -32010 | `UPSTREAM_ERROR` | shell | The blind-passthrough relay failed (unreachable / non-JSON). |
| -32020 | *(reserved: onion `onion_circuit_unavailable`)* | — | Reserved for the onion-routing contract; NOT minted by the control plane. |
| -32021 | *(reserved: onion `privacy_requires_local_node`)* | — | Reserved for the onion-routing contract. |
| -32022 | *(reserved: onion `onion_hops_out_of_range`)* | — | Reserved for the onion-routing contract. |
| -32030 | `UNAUTHORIZED` | shell | `control.*` called without a valid local control token. |
| -32031 | `NOT_SUPPORTED` | shell | A control operation this build/pin cannot perform (e.g. §21 sync without an identity). |
| -32032 | `CONTROL_ERROR` | shell | A control operation failed at runtime (distinct from bad input / absent capability). |

Read-path and upstream errors outside this table are relayed verbatim; this catalogue governs what
the **shell** mints plus the cross-boundary codes a client must be able to branch on.

---

## 11. Release and CI contract

11.1. **Tag-driven releases.** Pushing a `v*` tag runs `.github/workflows/release.yml`: a gate job
(`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`)
that MUST pass before any binary is built, then a per-OS/arch build matrix, then a single publish
job attaching all binaries to the GitHub Release. A push to `main` touching
`src/**`/`tests/**`/`build.rs`/`Cargo.toml`/`Cargo.lock`/the workflow runs gate + build (no
publish). Doc-only commits do not trigger the workflow.

11.2. **Dual asset naming (HARD RULE).** Every per-OS/arch binary MUST be published under TWO
filenames containing identical bytes:

- **`dig-node-<ver>-<os>-<arch>[.exe]`** — the canonical name; the dig-installer thin-shim's
  preferred stem.
- **`dig-companion-<ver>-<os>-<arch>[.exe]`** — the legacy name; apt.dig.net's Linux packaging
  resolves by exactly this template (`dig-companion-{ver}-linux-x64`, bare binary), and the
  installer keeps it as its pre-rename fallback.

`<ver>` is the tag without the leading `v`. Removing the legacy asset is a breaking change for
those consumers and MUST NOT be done while either still resolves it.

11.3. **Matrix.** `windows-x64` (x86_64-pc-windows-msvc), `linux-x64` (x86_64-unknown-linux-gnu),
`macos-arm64` (aarch64-apple-darwin), `macos-x64` (x86_64-apple-darwin, cross-compiled on
macos-14). No linux-arm64 asset is published (the Linux build graph pulls `openssl-sys` via the
Chia wallet SDK; no consumer requests it — apt.dig.net skips arm64 non-fatally and the installer
rejects arm64 tokens).

11.4. **Release hardening.** The release profile keeps `overflow-checks = true` (the read path
does offset/length arithmetic over untrusted serialized input).

---

## 12. Security properties (summary)

- **Never LAN-exposed:** loopback-only binds (§4.1); no `0.0.0.0` or `[::]`.
- **Anti-DNS-rebinding:** Host allowlist with 421 rejection (§4.2); CORS reflects only local
  origins (§4.3).
- **Read/control split:** read methods open to local consumers; `control.*` requires possession of
  the same-host capability file, compared in constant time, failing closed when unpersistable
  (§7.2–7.3).
- **Blind serving:** content reads return ciphertext + proofs; verification/decryption is the
  client's job (§1.3). The node never returns plaintext for content reads.
- **No secrets in artifacts:** the control token is generated at runtime, owner-restricted on
  Unix, and never committed or logged.

---

## 13. Conformance summary

| # | Contract | Must match | Where enforced / specified |
|---|---|---|---|
| 1 | Read-plane wire contract | `rpc.dig.net` byte-for-byte (dispatch IS `dig_node_core::handle_rpc`) | §1.3, §5; `dig-rpc-types` + docs.dig.net Protocol pages |
| 2 | `DIG_NODE_PORT` / `DIG_NODE_HOST` names | dig-installer + apt.dig.net expectations — never renamed | §3.1 |
| 3 | Shared cache default | Byte-identical dir to the DIG Browser's in-process node when `DIG_NODE_CACHE` unset | §3.5 |
| 4 | `dig.local` addressing | dig-installer hosts entry `127.0.0.2  dig.local`; listener `127.0.0.2:80`, best-effort | §4.1–4.2 |
| 5 | Host/CORS allowlist | `dig.local` / `localhost` / `127.0.0.1` / `127.0.0.2` / `::1` (+ `chrome-extension://` origins) | §4.2–4.3 |
| 6 | Method catalogue ↔ read path | drift guard: `local` resolves, `passthrough` returns `-32601` at the pinned rev | §5.5–5.6; `tests/openrpc_drift_guard.rs` |
| 7 | Error codes | Table §10 — stable numbers + UPPER_SNAKE names + origins | §10; `src/meta.rs` |
| 8 | CLI exit codes + `--json` envelopes | Table §8.4; one JSON object on stdout | §8; `src/cli.rs`, `tests/cli.rs` |
| 9 | Service label | `net.dignetwork.dig-node` across install/uninstall/start/stop/SCM dispatcher | §2.4, §9.4 |
| 10 | Release assets | Dual-named `dig-node-*` + legacy `dig-companion-*`, identical bytes, per §11.3 matrix | §11; `.github/workflows/release.yml` |
| 11 | Control-token scheme | `<config_dir>/control-token`, 64-hex, `X-Dig-Control-Token` / `params._control_token`, constant-time | §7.2–7.3 |
| 12 | Health/version/well-known shapes | §6 fields; additions additive only | §6; `src/meta.rs`, `src/server.rs` |
| 13 | Subscription persistence | `<cache>/subscriptions.json` schema-versioned, atomic, cross-process-locked | §14.1; `subscription.rs` |
| 14 | Autonomous sync fail-closed | chain-watch + gap-fill + read-path pin never serve/pull against an unconfirmable root | §14.2–14.4; `chainwatch.rs`, `lib.rs` |
| 15 | FFI C-ABI | `dig_runtime_start`/`dig_runtime_start_wallet` (wallet-only vs full) + `dig_rpc`/`dig_wallet_rpc`/`dig_free` + read-crypto `dig_read_verify_decrypt`/`dig_bytes_free` (`DIG_READ_*` codes) signatures + ownership/threading | §15, §15.1; `dig-runtime/src/lib.rs` |
| 16 | Wallet broadcast gate | dry-run default; mainnet push requires `DIG_WALLET_ALLOW_BROADCAST=1`; a dapp cannot force it | §16; `dig-wallet/src/lib.rs` |

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
  served locally (deduplicated: a backfill already in flight for `store:root` is not started twice).
  Enabled by default; toggle with the `DIG_NODE_BACKFILL_ON_MISS` environment variable.
- **Fail-closed.** Gap-fill never pulls against an unconfirmable root (the §14.2 decision gates it).
- **Verification invariant.** Every served module is verified against the chain-anchored root at SERVE,
  no matter how it arrived — a client read, a §21 whole-store sync, or a proactive/backfill gap-fill.

### 14.4. Read-path anchored-root pin

Every `dig.getContent` serve is PINNED to the store's chain-anchored tip root (#127): the node serves
against the on-chain current root or fails closed — it NEVER trusts an upstream-/host-reported root.

- For an **explicit-root** request the requested root MUST equal the resolved anchored tip; a mismatch
  is rejected. For a **rootless** request the node resolves the tip and serves against it.
- The pin fails closed with `-32005 ROOT_NOT_ANCHORED` (§10) on: a root mismatch, an unreachable chain,
  a store with no confirmed generation, or a rootless request under enforcement.
- The pin is ENFORCED by default. The ONLY opt-out is the explicit `DIG_NODE_PIN=off` (also `0`/`false`)
  environment variable, a named offline/local-development escape hatch — never the default. The pin is
  a NODE-side gate; clients still verify the returned proof against their own trust root regardless, so
  the opt-out only relaxes the node's serve gate for local dev.

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
surface, with native BLS signing. In the native browser it ALSO runs in-process via the §15 FFI
(`dig_wallet_rpc`), sharing one process-global wallet state with the loopback UI.

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
2. **Broadcast gate (dry-run default).** A signed spend bundle is pushed to mainnet ONLY when
   broadcasting is explicitly enabled by the process env `DIG_WALLET_ALLOW_BROADCAST=1`. The DEFAULT is
   a DRY RUN: the bundle is built and BLS-signed but NOT pushed (response status `"signed"`), spending
   no real funds. A dapp CANNOT force a broadcast — the request-level `broadcast` flag exists only on
   the local `/api/send` REST path; dapp-originated spends pass broadcast-intent internally and are
   gated SOLELY by the server-side env. With broadcasting disabled, a broadcast-intent local send is
   refused (`403` "broadcasting is disabled — set `DIG_WALLET_ALLOW_BROADCAST=1` to spend real mainnet
   funds") and a dapp spend degrades to a dry run.

### 16.3. Secret custody

Seed-reveal / private-key-export class methods (`export`, `exportMnemonic`, `chip0002_export`,
`chia_export`, `getMnemonic`, `getSecretKeys`, `getPrivateKey(s)`, `revealSeed`) are HARD-BLOCKED from
the dapp dispatch surface — they are absent from dispatch (fall to `501`) and are refused before any
forward to a delegated signer. The mnemonic is revealed ONLY through the local, password-gated,
self-origin `/api/export` UI route, never over the dapp/WC surface.

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

- **mTLS `9257`** (default; configurable). `POST /{method}` over TLS with Sage's shared-self-signed-cert
  MUTUAL-TLS model: the server accepts a client cert iff its DER is byte-identical to the server's own
  cert (a local-possession auth model — whoever can read the cert+key is authorized). Loopback only.
- **Plain-HTTP + CORS** (browser mirror). A browser/MV3 extension cannot present a client cert, so the
  identical surface is served over the loopback plain-HTTP transport with permissive CORS. Loopback only.

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
`401`, `wallet`/`internal` → `500`. An unknown/unsupported method is `404`; a malformed request body is
`400`.

18.5. **Local wallet database (SQLite).** The sync loop persists the wallet's chain state to a local
SQLite database (via `sqlx`), mirroring `sage-wallet`'s relational store: coins/CATs/derivations (and
NFT/DID/collection tables, plus an `offers` table for imported/built offers, #218) keyed by the wallet's
hardened AND unhardened HD puzzle hashes + CAT hints, plus the synced peak height. SQLite (NOT RocksDB): the workload is relational, multi-index, query-rich
and small (one wallet). Indexes on `puzzle_hash`, `asset_id`, a PARTIAL index on unspent
(`spent_height IS NULL`), and `created_height`; WAL enabled. Amounts are stored as decimal TEXT (full
`u64`/`u128` range, no `i64` overflow). This DB is the source of truth for a SYNCED wallet's data.

18.6. **Direct-peer sync (primary path).** Wallet chain data is obtained by connecting directly to Chia
full-node peers over the light-wallet protocol on `chia-wallet-sdk 0.30` `Peer` (`NodeType::Wallet`,
protocol `0.0.37`, the four DNS introducers, multi-peer, IPv6-first per §5.2), exactly as Sage does — NOT
via coinset for the wallet-data path. The node subscribes the wallet's puzzle hashes (BOTH hardened and
unhardened + CAT hints) with `request_puzzle_state(subscribe = true)`, applies the returned coin states,
then consumes `coin_state_update` pushes into the DB. A reorg (a `coin_state_update` whose `fork_height`
is below the current peak) rolls the DB back above the fork — coins created above it are deleted, coins
spent above it become unspent again — then applies the update's coin states and advances the peak.

18.7. **Fallback tier + sync-state-gated routing.** `chia-query` (coinset.org + non-subscribing peer
point-reads) is reused AS-IS as a fallback tier — never the primary. The B.3 subscription loop is NOT
added to `chia-query`. Every wallet-data read selects its source:

| Condition                                            | Source           |
|------------------------------------------------------|------------------|
| Wallet's own data, DB synced to peak                 | Local wallet DB  |
| Wallet's own data, DB still syncing                  | Fallback tier    |
| Chain data not scoped to this wallet, not in the DB  | Fallback tier    |

So a caller never blocks on an unsynced replica. `get_sync_status` reports the gating sync state.

18.8. **Method surface — reads (served).** `login`, `logout`, `get_version`,
`get_sync_status`, `check_address`, `get_derivations`, `get_are_coins_spendable`,
`get_spendable_coin_count`, `get_coins`, `get_coins_by_ids`, `get_cats`, `get_all_cats`, `get_token`,
`get_dids`, `get_nfts`, `get_nft`, `get_nft_data`, `get_nft_collections`, `get_nft_collection`,
`get_transactions`, `get_transaction`, `get_pending_transactions`, `is_asset_owned`, `get_key`,
`get_keys`. Coins and CAT balances/records are fully synced and served; transactions are derived from the
coin table grouped by created/spent height; NFT/DID/collection reads return the rows the sync
reconstruction populates (§18.11). `get_pending_transactions` is empty (no pending-tracking store yet).

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
read it back, `cancel_offer` marks it cancelled. Sage's per-endpoint `auto_submit` defaults are matched
(offers/mint/transfer default `false`; `make_offer.auto_import` defaults `true`).

18.10. **Signing + custody (C.6).** The node signs with its custodied seed only for node-class /
DIG-Browser callers (a `WalletSigner` over the wallet's synthetic p2 keys). Secret-touching endpoints
(`get_secret_key`/`generate_mnemonic`/`import_key`/exportMnemonic/revealSeed) stay 501'd + loopback+token
gated, NEVER reachable from a dapp/non-loopback origin. The MV3 extension self-custodies and does NOT use
the node's sign/spend path.

18.11. **NFT/DID/CAT reconstruction.** A raw `CoinState` does not reveal a coin's asset kind — that lives
in the coin's puzzle, revealed only when its parent is spent. Reconstruction uncurries the parent spend
(via the `Nft`/`Did`/`Cat` driver parsers) to populate the `nfts`/`dids`/`nft_collections` tables and to
attribute CAT coins to their asset id (TAIL hash) in the `coins` table (so `get_cats`/`get_token` become
complete). Parent spends are fetched through a `LineageSource` (out-of-DB lineage reads, B.5). Reads only.

18.12. **Deferred to follow-on units.** The off-chain NFT data-blob/CHIP-0015 metadata fetch
(`get_nft_data` returns on-chain fields; the metadata JSON surfaces when fetched), `exercise_options`
(§18.15 — a documented, non-silent follow-on), and real image-derived theme content (§18.16 — this
backend stores a placeholder). The service bring-up that starts the dual-transport server and invokes
reconstruction after sync (via a peer/coinset `LineageSource`) is the remaining integration.

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
from `get_peers`; `peak_height` reports `0` until live per-peer telemetry is wired to the sync loop —
never fabricated. `set_discover_peers`/`set_target_peers`/`set_delta_sync`/`set_delta_sync_override`/
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
