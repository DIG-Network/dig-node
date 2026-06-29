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
| `DIG_NODE_CACHE` | `%LOCALAPPDATA%\DigNode\cache` / `$HOME/DigNode/cache` | On-disk cache dir for synced `.dig` modules (owned by `dig-node`). |
| `DIG_NODE_CACHE_CAP` | `1 GiB` | Cache size cap (floored at 64 MiB), LRU-evicted. Also settable via the `cache.setCapBytes` RPC. |

## JSON-RPC surface

`POST /` speaks JSON-RPC 2.0, the same contract `rpc.dig.net` and the native DIG Browser's
in-process node expose:

| Method | Behaviour |
|---|---|
| `dig.getContent` / `dig.getCapsule` | **Verified retrieval** — returns blind **ciphertext + a Merkle inclusion proof + chunk lengths** (`{ ciphertext, root, complete, next_offset?, inclusion_proof, chunk_lens, …, source }`). Served **local-first** from a cached `.dig` module, else proxied to the upstream verbatim (so the proxy path carries `total_length` / `offset` too) and the window cached. `source` is `local` or `remote`. **The client (extension/hub/browser) verifies + decrypts** — the companion mirrors the ciphertext contract, it does not return plaintext. |
| `dig.getAnchoredRoot` | The store's **chain-anchored tip root**, resolved on-chain by walking the DataStore singleton lineage on coinset.org (the trusted root for the extension's `dig://` root-pinning). |
| `cache.getConfig` / `cache.setCapBytes` / `cache.clear` | On-disk cache config (`cap_bytes` floored at 64 MiB). |
| `cache.listCached` / `cache.removeCached` / `cache.fetchAndCache` | Cached-capsule manager (`storeId:rootHash`). |
| `rpc.discover` | **Method discovery** — returns this node's OpenRPC document (the standard OpenRPC discovery method), so a client can introspect every method + error over the wire with no out-of-band knowledge. |
| `dig.getProof`, `dig.listCapsules`, `dig.getManifest`, *anything else* | **Blind passthrough** — relayed verbatim to the upstream, so the node stays a correct transparent proxy for methods it doesn't resolve locally. |

## Discovery & health endpoints

A single fetch tells an agent what the node is, where it serves, and what it speaks:

| Endpoint | Returns |
|---|---|
| `GET /health` | `{ status, service:"dig-node", version, commit, mode, addr, upstream, cache:{ dir, cap_bytes, used_bytes }, methods:[…] }` — extends the original health body (existing probes keep parsing `status`/`version`/`mode`/`upstream`/`cache`). |
| `GET /version` | `{ service:"dig-node", version, commit, dig_node_version, protocol }` — the build fingerprint, to correlate a running node to an exact source revision. |
| `GET /openrpc.json` | The OpenRPC document for the JSON-RPC surface (methods + error catalogue), generated from the method/error source so it cannot drift. |
| `GET /.well-known/dig-node.json` | The canonical discovery doc: identity, bound `addr`, cache (`dir`/`cap_bytes`/`used_bytes`), the method catalogue, the error catalogue, and pointers to the OpenRPC/health/version endpoints. |

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

## How the read path is wired (the important design decision)

The companion does **not** reimplement the DIG read path — it depends on digstore's **`dig-node`**
crate (pinned to the `v0.5.29` release tag) and routes every request to `dig_node::handle_rpc`. This
is the **same node the native DIG Browser runs in-process**, so the companion and the browser share
one read path and one cache contract.

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
  server.rs       axum HTTP server: /health, /version, /openrpc.json, /.well-known/dig-node.json, CORS,
                  POST / → dig_node::handle_rpc (+ rpc.discover), passthrough fallback
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
