# dig-companion (the **dig-node** service)

The **localhost DIG node** for the [DIG Chrome extension](https://github.com/DIG-Network/dig-chrome-extension),
shipped as a **self-contained, cross-platform Rust binary** that installs as an **OS service**
(Windows, Linux, macOS).

> **Naming.** The binary is `dig-companion` (kept stable so existing installs/clients keep
> working), but the **service it runs is `dig-node`** — the canonical, user-facing name for the
> local DIG node (per the ecosystem `SYSTEM.md`). Every machine-readable surface (`/health`,
> `/version`, `--json`) identifies itself as `dig-node`. See [`USER_JOURNEY.md`](USER_JOURNEY.md).

The extension resolves `chia://` (DIG) URLs by fetching encrypted, Merkle-proven content over a DIG
RPC and then **verifying + decrypting it in the extension**. By default it talks to `rpc.dig.net`;
pointing its `server.host` setting at `dig-companion` makes that RPC **local**. The companion speaks
the **same wire contract as `rpc.dig.net`** — because it routes every request to digstore's
`dig_node::handle_rpc`, the exact local-first node the native [DIG Browser](https://github.com/DIG-Network/DIG_Browser)
runs in-process. So the extension works against it byte-for-byte, with the bonus that any `.dig`
store the node has cached locally is served without leaving the machine.

> **v0.3 — now a Rust OS-service binary.** The previous Node implementation (v0.2) is retained as a
> documented reference under [`node/`](node/), but the **shipped artifact is the Rust `dig-companion`
> binary**. A single binary has no runtime dependency (no Node install required) and installs cleanly
> as a Windows/Linux/macOS service — which a Node process does not do reliably, especially on Windows.

## Install as a service

Download (or build — see below) the `dig-companion` binary for your OS, then:

```bash
dig-companion install     # register as an auto-starting OS service on 127.0.0.1:8080
dig-companion start       # start it now
dig-companion status      # confirm it's serving (probes /health)
```

To remove it:

```bash
dig-companion stop
dig-companion uninstall
```

### Per-OS notes

| OS | Service backend | Privilege | Runs as |
|---|---|---|---|
| **Windows** | Service Control Manager (SCM) | **Administrator required** for `install`/`uninstall` | `LocalSystem` |
| **Linux** | systemd (user unit) | no root needed | the installing user |
| **macOS** | launchd (user agent) | no root needed | the installing user |

- **Windows:** the SCM has no per-user services, so `install`/`uninstall` must run from an **elevated
  (Run as administrator)** terminal. `dig-companion` detects a non-elevated console and tells you,
  rather than failing deep inside `sc.exe`. The installed service runs the binary's internal
  `run-service` entrypoint, which speaks the Windows Service Control Protocol (so the SCM does not
  kill it with error 1053). After install it auto-starts on boot.
- **Linux / macOS:** the service installs at **user level** (systemd `--user` / a launchd GUI agent),
  so no `sudo` is needed and it runs as you. (systemd user services start at login; enable
  linger — `loginctl enable-linger $USER` — if you want it running without an active session.)

## Point the extension at it

In the DIG Chrome extension's options, set **server host** to:

```
localhost:8080
```

(The extension defaults to `localhost:80`; port 80 needs elevated privileges on most OSes, so the
companion defaults to `8080`. Set the extension to match, or run the companion on `80` if you can.)

## Run in the foreground (no service)

```bash
dig-companion run         # serve on 127.0.0.1:8080 until Ctrl-C
# or simply:
dig-companion             # bare invocation == run
```

## Configuration

All knobs are environment variables (read at startup; `install` records the current values into the
service's environment so the service serves identically):

| Env var | Default | Meaning |
|---|---|---|
| `DIG_COMPANION_PORT` | `8080` | Port the companion listens on (`127.0.0.1`). |
| `DIG_COMPANION_HOST` | `127.0.0.1` | Bind address (loopback — the companion is a same-machine endpoint). |
| `DIG_RPC_UPSTREAM` | `https://rpc.dig.net` | Upstream DIG RPC the embedded node proxies ciphertext/proof requests to on a local cache miss, and relays unhandled methods to. |
| `DIG_NODE_CACHE` | `%LOCALAPPDATA%\DigNode\cache` / `$HOME/DigNode/cache` | On-disk cache dir for synced `.dig` modules (owned by `dig-node`). **Leave it unset to share one cache with the DIG Browser** — see below. |
| `DIG_NODE_CACHE_CAP` | `1 GiB` | Cache size cap (floored at 64 MiB), LRU-evicted. Also settable via the `cache.setCapBytes` RPC. |

### Shared `.dig` cache with the DIG Browser (#96)

`dig-companion` and the native [DIG Browser](https://github.com/DIG-Network/DIG_Browser) both embed
digstore's `dig-node`, and **both default to the SAME on-disk cache dir**
(`%LOCALAPPDATA%\DigNode\cache` on Windows, `$HOME/DigNode/cache` on Linux/macOS). So when both are
installed they **share ONE cache** — a capsule fetched by the browser is served from disk by the
standalone service and vice-versa, with **no double-store**.

- **Omit `DIG_NODE_CACHE`** (the default) to keep that sharing — the companion does **not** invent a
  path, it leaves dig-node to resolve its shared canonical default. dig-node makes that shared dir
  safe for two processes at once: atomic content-addressed module writes (so two writers converge
  with no partial files) plus a cross-process advisory lock around eviction and the config
  read-modify-write. (Requires the `dig-node` crate at the #95/#96 Pass A revision this repo pins.)
- **Set `DIG_NODE_CACHE`** only to move that shared cache to an explicit location (a service data
  dir, or a volume shared between machines). If you do, set the **same** value for the browser's
  launch environment so the two keep sharing one cache; pointing them at different dirs gives each
  its own (un-shared) cache. `install` records an explicit `DIG_NODE_CACHE` into the service
  environment so the installed service uses the same dir you installed it with.
- **Is the cache actually shared right now?** `GET /health` and `cache.getConfig` report a
  `cache.shared` boolean: `true` = the shared canonical dir, `false` = dig-node fell back to a
  process-private dir because the canonical dir was unwritable (it logs a one-shot warning and keeps
  serving, just un-shared for that session). `cache.getConfig` also returns the effective
  `cache_dir` path.

## JSON-RPC surface

`POST /` speaks JSON-RPC 2.0, the same contract `rpc.dig.net` and the native DIG Browser's
in-process node expose:

| Method | Behaviour |
|---|---|
| `dig.getContent` / `dig.getCapsule` | **Verified retrieval** — returns blind **ciphertext + a Merkle inclusion proof + chunk lengths** (`{ ciphertext, root, complete, next_offset?, inclusion_proof, chunk_lens, …, source }`). Served **local-first** from a cached `.dig` module, else proxied to the upstream verbatim (so the proxy path carries `total_length` / `offset` too) and the window cached. `source` is `local` or `remote`. **The client (extension/hub/browser) verifies + decrypts** — the companion mirrors the ciphertext contract, it does not return plaintext. |
| `dig.getAnchoredRoot` | The store's **chain-anchored tip root**, resolved on-chain by walking the DataStore singleton lineage on coinset.org (the trusted root for the extension's `dig://` root-pinning). |
| `cache.getConfig` / `cache.setCapBytes` / `cache.clear` | On-disk cache config: `{ cap_bytes (floored at 64 MiB), used_bytes, cache_dir, shared }` — `cache_dir` is the effective dir and `shared` whether it is the canonical dir shared with the DIG Browser (#96). |
| `cache.listCached` / `cache.removeCached` / `cache.fetchAndCache` | Cached-capsule manager (`storeId:rootHash`). |
| `rpc.discover` | **Method discovery** — returns this node's OpenRPC document (the standard OpenRPC discovery method), so a client can introspect every method + error over the wire with no out-of-band knowledge. |
| `control.*` | **CONTROL / admin surface** (loopback-only + **local-token gated** — see below). Manage the node: hosted/pinned stores, cache, §21 sync, config. Read methods above stay open; only `control.*` requires the token. |
| `dig.getProof`, `dig.listCapsules`, `dig.getManifest`, *anything else* | **Blind passthrough** — relayed verbatim to the upstream, so the node stays a correct transparent proxy for methods it doesn't resolve locally. |

## Control / admin surface (`control.*`) — manage the node

Beside the open **read** RPC, the node exposes a **CONTROL / admin** surface so a same-host
controller — the DIG Browser **"My Node"** UI, or any local tool — can MANAGE the node. This is the
server side of SYSTEM.md → *"the browser is also the dig-node's CONTROLLER UI"* (dig-node =
**serve + be-controllable**; the browser = **consume + control**).

### Security — loopback-only + locally authorized

Two layers gate the control surface (the read methods are **not** gated):

1. **Loopback-only** — the whole server binds `127.0.0.1`, so nothing off-machine can reach any method.
2. **Local authorization** for the mutating `control.*` namespace. A random **control token** (32 bytes,
   64-hex) is generated at first run into the node's config dir at **`<config_dir>/control-token`**
   (next to dig-node's `config.json`; `0600` on Unix). A same-host controller reads that file — it can,
   because it runs as the same user on the same machine — and presents the token on every `control.*`
   call, as the **`X-Dig-Control-Token`** request header **or** a **`params._control_token`** field. A
   call without a valid token is rejected with **`UNAUTHORIZED`** (`-32020`). Token verification is
   constant-time; the token is generated at runtime and **never committed**.

This is the standard local-capability-file pattern (cf. Chia's daemon / Bitcoin's cookie auth):
possession of the on-disk token *is* authorization, so a random web page (which cannot read a local
file) is rejected even though it can reach loopback, while the legitimate local controller is allowed.

### Methods

All `control.*` methods require the local control token. Params are a JSON object; `store` is a
capsule reference `storeId` or `storeId:rootHash` (each part lowercase 64-hex).

| Method | Params | Result |
|---|---|---|
| `control.status` | — | `{ running, service, version, commit, dig_node_version, protocol, uptime_secs, addr, upstream, cache:{cap_bytes,used_bytes,dir,shared}, hosted_store_count, cached_capsule_count, pinned_store_count, sync:{available} }` |
| `control.config.get` | — | `{ addr, port, upstream, upstream_override, cache_dir, cache_shared, config_path, sync_available }` |
| `control.config.setUpstream` | `{ upstream }` | `{ upstream, requires_restart:true }` — persisted; the running node captured its upstream at startup, so the change takes effect on the next start. A blank `upstream` clears the override. |
| `control.cache.get` | — | `{ cap_bytes, used_bytes, dir, shared }` |
| `control.cache.setCap` | `{ cap_bytes }` | `{ cap_bytes }` (floored at 64 MiB) |
| `control.cache.clear` | — | `{ cleared:true }` |
| `control.hostedStores.list` | — | `{ stores:[ { store_id, pinned, capsule_count, total_bytes, capsules:[{capsule,root,size_bytes,last_used_unix_ms}] } ] }` |
| `control.hostedStores.pin` | `{ store }` | `{ store_id, root, pinned:true, fetch:{status,…} }` — records the pin; pre-fetches the capsule via §21 sync when a concrete root is given. |
| `control.hostedStores.unpin` | `{ store }` | `{ store_id, unpinned, evicted_capsules }` — removes the pin and evicts the store's cached capsules. |
| `control.hostedStores.status` | `{ store }` | `{ store_id, pinned, capsule_count, total_bytes, capsules:[…] }` |
| `control.sync.status` | — | `{ available, method:"section-21-whole-store-sync", pinned_total, pinned_synced, whole_store_trigger_supported }` |
| `control.sync.trigger` | `{ store }` (= `storeId:rootHash`) or `{ store_id, root }` | `{ store_id, root, status:"synced", size_bytes, served_root }`, or `NOT_SUPPORTED` (`-32021`) if no §21 identity. |

**What's proxied vs. owned.** Cache + sync operations proxy to digstore's `dig-node` crate
(`cache_*`, `clear_cache`, `set_cache_cap_bytes`, `Node::cache_fetch_and_cache` / `cache_remove_cached`
/ `cache_list_cached`) — the companion never duplicates the cache/read logic. The shell owns only the
small state the crate does not model: the **pin registry** (`pinned_stores`) and the **upstream
override** (`upstream_override`), persisted under the companion's own keys in dig-node's shared
`config.json` (atomic temp+rename writes that never clobber dig-node's keys).

### Driving it from the DIG Browser controller (part b)

The DIG Browser "My Node" UI calls these methods over loopback (`http://localhost:<port>/`), reading
the token from `<config_dir>/control-token` and sending it as `X-Dig-Control-Token`. Discover the
whole surface — methods, `x-requires-auth` flags, the `info.x-control-auth` token scheme, and the
error catalogue — from **`GET /openrpc.json`** or **`rpc.discover`**.

## Discovery & health endpoints

A single fetch tells an agent what the node is, where it serves, and what it speaks:

| Endpoint | Returns |
|---|---|
| `GET /health` | `{ status, service:"dig-node", version, commit, mode, addr, upstream, cache:{ dir, cap_bytes, used_bytes, shared }, methods:[…] }` — extends the original health body (existing probes keep parsing `status`/`version`/`mode`/`upstream`/`cache`). `cache.shared` (#96) tells whether the cache is the dir shared with the DIG Browser. |
| `GET /version` | `{ service:"dig-node", version, commit, dig_node_version, protocol }` — the build fingerprint, to correlate a running node to an exact source revision. |
| `GET /openrpc.json` | The OpenRPC document for the JSON-RPC surface (methods + error catalogue), generated from the method/error source so it cannot drift. |
| `GET /.well-known/dig-node.json` | The canonical discovery doc: identity, bound `addr`, cache (`dir`/`cap_bytes`/`used_bytes`/`shared`), the method catalogue, the error catalogue, and pointers to the OpenRPC/health/version endpoints. |

CORS reflects `chrome-extension://` (and `http://localhost`) origins so the extension can call it.

## Machine-readable contracts (agent-friendly)

### CLI `--json`

Every subcommand accepts the global `--json` flag: machine output goes to **stdout**, human prose
to **stderr**.

```bash
dig-companion status --json
# {"ok":true,"action":"status","service":"dig-node","version":"0.3.0","serving":false,"addr":"127.0.0.1:8080",…}

dig-companion install --json
# {"ok":true,"action":"install","installed":true,"registered":true,"started":false,"label":"…","scope":"system","addr":"127.0.0.1:8080",…}
```

On failure: `{ "ok":false, "action":…, "error":{ "code", "exit_code", "message", "hint" } }`.

### Exit-code table

Each failure class maps to a **distinct** process exit code (not a generic `1`), backed by the
typed `ExitCode` enum in `src/cli.rs`:

| Exit | Code (`UPPER_SNAKE`) | Meaning |
|---|---|---|
| 0 | `OK` | Success. |
| 1 | `NOT_SERVING` | `status`: the node is not responding (scriptable "is it up?"). |
| 2 | `USAGE` | Bad arguments / usage error. |
| 3 | `PERMISSION_DENIED` | `install`/`uninstall` need an elevated (Administrator) console (Windows). |
| 4 | `SERVICE_FAILED` | A service operation failed (register/start/stop/uninstall). |
| 5 | `BIND_FAILED` | `run`: could not bind the loopback address. |
| 6 | `IO_ERROR` | Other I/O error. |

### JSON-RPC error-code catalogue

Wire errors carry a stable UPPER_SNAKE symbolic name in `error.data.code` (+ `error.data.origin`
distinguishing companion-shell errors from upstream/boundary ones), beside the numeric JSON-RPC
`code`. Catalogued in `src/meta.rs` (the `ErrorCode` enum), embedded in `/openrpc.json` and
`/.well-known/dig-node.json`:

| JSON-RPC code | Name | Origin | Meaning |
|---|---|---|---|
| -32700 | `PARSE_ERROR` | shell | Request body was not valid JSON. |
| -32600 | `INVALID_REQUEST` | shell | Not a single JSON-RPC object (batch arrays unsupported). |
| -32601 | `METHOD_NOT_FOUND` | boundary | Not resolved locally or by the upstream. |
| -32602 | `INVALID_PARAMS` | upstream | Invalid or missing method parameters. |
| -32000 | `DISPATCH_FAILED` | shell | The node failed to dispatch the request. |
| -32010 | `UPSTREAM_ERROR` | shell | The blind-passthrough relay to the upstream failed. |
| -32020 | `UNAUTHORIZED` | shell | A `control.*` method was called without a valid local control token. |
| -32021 | `NOT_SUPPORTED` | shell | A control op the node build can't perform (e.g. §21 sync with no identity). |
| -32022 | `CONTROL_ERROR` | shell | A control operation failed at runtime (e.g. could not persist the pin registry). |

## How the read path is wired (the important design decision)

The companion does **not** reimplement the DIG read path — it depends on digstore's **`dig-node`**
crate (pinned to the #95/#96 **Pass A** commit, `b2632c4`, which ships the shared-cache work; no
release tag contains it yet, so the dep is pinned to a `rev`) and routes every request to
`dig_node::handle_rpc`. This is the **same node the native DIG Browser runs in-process**, so the
companion and the browser share one read path, one cache, and one cache contract (see "Shared `.dig`
cache" above).

- `dig-node` is a **clean Cargo dependency**: the guest-wasm build prerequisite that gates
  `digstore-cli` (its `build.rs` embeds the compiled guest) does **not** apply to `dig-node`, which
  depends only on `digstore-host` / `-core` / `-remote` / `-chain`. No special build step is needed.
- All TLS is `rustls` (no system OpenSSL), so the binary is genuinely self-contained.
- The companion adds only the **shell** around that node: the HTTP server, CORS, `/health`, request
  normalisation, a **blind-passthrough fallback** (`dig-node` answers only `dig.getContent` /
  `dig.getAnchoredRoot` / `cache.*` and returns "method not found" for the rest; the companion
  relays those to the upstream), and the OS-service install/management.

## Build from source

Requires Rust (the repo pins `1.94.1`).

```bash
cargo build --release          # → target/release/dig-companion[.exe]
cargo test                     # routing, config, cache-key, service helpers + an in-process server test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

The first build fetches the `dig-node` git dependency (and its digstore/wasmtime tree), so it takes
a few minutes; subsequent builds are fast.

## Architecture

```
build.rs          captures the git commit SHA at build time (the /version `commit` field)
src/
  main.rs         CLI (run / run-service / install / uninstall / start / stop / status) + --json rendering
  lib.rs          module wiring
  config.rs       env-driven Config (port/host/upstream) — pure, tested
  meta.rs         self-describing surface: version/build info, method catalogue, ErrorCode catalogue,
                  OpenRPC + /.well-known/dig-node.json documents — pure, tested
  cli.rs          --json envelopes + the differentiated ExitCode table — pure, tested
  rpc.rs          JSON-RPC routing + request normalisation + catalogued error envelopes — pure, tested
  control.rs      CONTROL/admin surface (control.*): hosted-stores/cache/sync/config management +
                  the loopback-only local-token auth gate + pin registry — pure helpers tested
  server.rs       axum HTTP server: /health, /version, /openrpc.json, /.well-known/dig-node.json, CORS,
                  POST / → dig_node::handle_rpc (+ rpc.discover) + the gated control plane, passthrough fallback
  service.rs      OS-service install/uninstall/start/stop/status (service-manager) + /health status probe
  win_service.rs  Windows Service Control Protocol entrypoint (windows-service; Windows only)
node/             the Node v0.2 reference implementation (documentation only — NOT the shipped artifact)
USER_JOURNEY.md   the dig-node user/operator/agent journey, surfaces, and ecosystem hand-offs
```

## Relationship to the rest of the ecosystem

- The wire contract is identical to `rpc.dig.net` and to the native browser's in-process node,
  because all three are (or route to) `dig_node::handle_rpc`. Clients see one consistent local-node
  API across the extension and the native browser.
- The verify/decrypt read-crypto lives in the **extension** (the same `dig_client` WASM the hub uses);
  the companion serves the ciphertext + proof the extension consumes. See the repo `SYSTEM.md`.

## License

MIT (the binary). The bundled `dig-node` read path is GPL-2.0-only (digstore). See the DIG Network
organization.
