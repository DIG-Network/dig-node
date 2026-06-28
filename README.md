# dig-companion

The **localhost DIG node** for the [DIG Chrome extension](https://github.com/DIG-Network/dig-chrome-extension),
shipped as a **self-contained, cross-platform Rust binary** that installs as an **OS service**
(Windows, Linux, macOS).

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
| `dig.getProof`, `dig.listCapsules`, `dig.getManifest`, *anything else* | **Blind passthrough** — relayed verbatim to the upstream, so the companion stays a correct transparent proxy for methods it doesn't resolve locally. |

`GET /health` → `{ status, version, mode, upstream, cache: { cap_bytes, used_bytes } }`.

CORS reflects `chrome-extension://` (and `http://localhost`) origins so the extension can call it.

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
src/
  main.rs         CLI (run / run-service / install / uninstall / start / stop / status)
  lib.rs          module wiring
  config.rs       env-driven Config (port/host/upstream) — pure, tested
  rpc.rs          JSON-RPC routing + request normalisation — pure, tested
  server.rs       axum HTTP server: /health, CORS, POST / → dig_node::handle_rpc, passthrough fallback
  service.rs      OS-service install/uninstall/start/stop/status (service-manager) + /health status probe
  win_service.rs  Windows Service Control Protocol entrypoint (windows-service; Windows only)
node/             the Node v0.2 reference implementation (documentation only — NOT the shipped artifact)
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
