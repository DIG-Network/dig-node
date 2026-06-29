# dig-node — user & operator journey

> **Naming.** The shipped binary is `dig-companion` (kept stable so existing installs/clients
> keep working), but the **service it runs is `dig-node`** — the canonical, user-facing name for
> the local DIG node (per `SYSTEM.md` → *Canonical terminology & branding*). Everything the user
> sees and every machine-readable surface identifies itself as `dig-node`.

`dig-node` is the **localhost DIG node** that the [DIG Chrome extension](https://github.com/DIG-Network/dig-chrome-extension)
(and any DIG client) resolves `chia://` content through, so retrieval happens **on the user's own
machine** instead of always hitting `rpc.dig.net`. It is the standalone-service twin of the native
[DIG Browser](https://github.com/DIG-Network/DIG_Browser)'s in-process node and of `digstore serve` —
all three are (or route to) digstore's `dig_node::handle_rpc`, so they share one read path and one
cache contract.

---

## Who is on this journey

1. **End user** — wants `chia://` content to load fast and verified, served locally, without
   thinking about protocols. Installs `dig-node` once; it runs in the background as an OS service.
2. **Operator / advanced user** — runs/monitors the node, sets the cache cap, points the extension
   at it, scripts install/health from CI or a dotfiles bootstrap.
3. **Agent / integrating tool** — discovers and drives the node programmatically: introspects what
   it is (`/version`, `/.well-known/dig-node.json`), what it speaks (`/openrpc.json`, `rpc.discover`),
   and branches on stable error/exit codes — with zero out-of-band knowledge.

---

## The journey, end to end

### 1. Install (via dig-installer or a direct download)

The user installs `dig-node` as part of the DIG experience. The recommended path is the
**[dig-installer](https://github.com/DIG-Network/dig-installer)**, which downloads the pinned
`dig-companion` binary for the platform and runs `dig-companion install`. The binary can also be
downloaded directly from the repo's GitHub Releases (per-OS, self-contained — no Node runtime).

```bash
dig-companion install     # register as an auto-starting OS service on 127.0.0.1:8080
dig-companion start       # start it now
dig-companion status      # confirm it's serving (probes /health)
```

| OS | Service backend | Privilege | Runs as |
|---|---|---|---|
| **Windows** | Service Control Manager (SCM) | **Administrator** for install/uninstall | `LocalSystem` |
| **Linux** | systemd (user unit) | no root needed | the installing user |
| **macOS** | launchd (user agent) | no root needed | the installing user |

On Windows the SCM has no per-user services, so install/uninstall need an elevated console; the CLI
detects a non-elevated shell and reports it (exit code `PERMISSION_DENIED` / 3) rather than failing
deep inside `sc.exe`. The installed Windows service runs the hidden `run-service` entrypoint, which
speaks the Windows Service Control Protocol so the SCM does not kill it with error 1053.

### 2. The service runs

Once installed, `dig-node` runs on `127.0.0.1:8080` (configurable — see the env table in the
README) and auto-starts on boot/login. It is **loopback-only**: it is a same-machine endpoint for
the browser/extension, never a public server.

### 3. The extension (or browser) points at it

In the DIG Chrome extension's options, the **server host** is set to `localhost:8080`. From then on
the extension resolves `chia://` URLs through the local node instead of `rpc.dig.net`.

### 4. Resolving `chia://` content (the read path)

When a `chia://` resource is requested:

1. The client (extension) calls `POST /` with JSON-RPC `dig.getContent` (`{store_id, root,
   retrieval_key, offset, length}`).
2. `dig-node` answers **local-first**: if the capsule (`storeId:rootHash`) is in the local cache it
   serves the **blind ciphertext + Merkle inclusion proof + chunk lengths** straight from disk.
3. On a cache miss it **blind-fetches** ciphertext + proof from the upstream DIG RPC
   (`DIG_RPC_UPSTREAM`, default `https://rpc.dig.net`), caches the window, and returns it.
4. The **client verifies the Merkle proof and decrypts** the content (the read-crypto lives in the
   extension/browser — the local node mirrors the ciphertext contract, it never returns plaintext;
   the "blind host" property is preserved for remote hosts, while the *local* node legitimately
   serves what the user's own machine fetched).

`dig.getAnchoredRoot` resolves a store's chain-anchored tip root; `cache.*` methods configure and
inspect the on-disk cache; everything else (`dig.getProof`, `dig.listCapsules`, `dig.getManifest`,
…) is **blind-passthrough** relayed verbatim to the upstream, so the node stays a correct
transparent proxy.

### 5. The local cache

`dig-node` keeps a disk cache of synced `.dig` modules keyed by `storeId:rootHash`, capped (default
1 GiB, floored at 64 MiB, LRU-evicted) and settable live via `cache.setCapBytes`. The cache dir is
reported in `/health` and `/.well-known/dig-node.json` so an operator/agent can find it.

> **Note (future work):** task #91 (dual loopback listener `127.0.0.2:80` + `localhost` with a
> `dig.local` Host allowlist) and task #96 (shared `.dig` cache across the browser/node) will change
> this repo's networking/cache. They are **out of scope** for the agent-friendly pass documented
> here.

### 6. Control the node from a controller UI (the DIG Browser "My Node")

When a local `dig-node` is present, the DIG Browser's **"My Node"** surface drives the node's
**CONTROL / admin** RPCs (`control.*`) so the user runs *and* manages their node from the browser:
list/pin/unpin hosted stores, view/clear/cap the cache, check §21 sync status / trigger a sync, and
get/set config (upstream). This is the server side of SYSTEM.md → *"the browser is also the
dig-node's CONTROLLER UI"* — dig-node = **serve + be-controllable**; the browser = **consume +
control**.

The control surface is **loopback-only + locally authorized**: a random **control token** is
generated at first run into `<config_dir>/control-token` (next to `config.json`). The controller
reads that file (same user, same machine) and presents the token on every `control.*` call as the
`X-Dig-Control-Token` header (or `params._control_token`). Read methods are **not** gated; a
`control.*` call without the token is rejected `UNAUTHORIZED` (-32020). See the README → *Control /
admin surface* for the full method/param/result table.

### 7. Manage / uninstall

```bash
dig-companion stop
dig-companion uninstall
```

---

## Surfaces (what the node exposes)

### Human / operator CLI

`run` · `install` · `uninstall` · `start` · `stop` · `status` — plus the global `--json` flag on
every subcommand (machine output to stdout, prose to stderr).

### HTTP endpoints (loopback)

| Endpoint | Purpose |
|---|---|
| `POST /` | JSON-RPC 2.0 — the read path (`dig.getContent`, `dig.getAnchoredRoot`, `cache.*`, passthrough, `rpc.discover`) **and** the gated `control.*` admin surface. |
| `GET /health` | Liveness + mode + cache stats, plus `service`, `commit`, bound `addr`, cache `dir`, and the `methods` catalogue. |
| `GET /version` | Build fingerprint: `{ service, version, commit, dig_node_version, protocol }`. |
| `GET /openrpc.json` | The OpenRPC document for the JSON-RPC surface (methods + error catalogue). |
| `GET /.well-known/dig-node.json` | Canonical discovery doc: identity, addr, cache, methods, errors, spec pointers. |

### Machine-readable contracts (agent-friendly)

- **`--json`** on the CLI: success → `{ ok:true, action, service, version, …result }`; failure →
  `{ ok:false, error:{ code, exit_code, message, hint } }`.
- **Exit-code table** (documented in the README + `src/cli.rs`): `0 OK`, `1 NOT_SERVING`,
  `2 USAGE`, `3 PERMISSION_DENIED`, `4 SERVICE_FAILED`, `5 BIND_FAILED`, `6 IO_ERROR`.
- **Stable JSON-RPC error codes** (UPPER_SNAKE in `error.data.code`): `PARSE_ERROR` (-32700),
  `INVALID_REQUEST` (-32600), `METHOD_NOT_FOUND` (-32601), `INVALID_PARAMS` (-32602),
  `DISPATCH_FAILED` (-32000, shell), `UPSTREAM_ERROR` (-32010, shell), and the control-plane codes
  `UNAUTHORIZED` (-32020), `NOT_SUPPORTED` (-32021), `CONTROL_ERROR` (-32022). The `data.origin`
  field distinguishes companion-shell errors from upstream/boundary ones.
- **`rpc.discover`**: returns the OpenRPC document over the wire, so an agent can introspect the
  full method + error surface (including `x-requires-auth` per method and the `info.x-control-auth`
  token scheme) with no out-of-band knowledge.

---

## Ecosystem hand-offs

| Hands off to / from | What crosses the boundary |
|---|---|
| **dig-installer → dig-node** | Installer downloads the pinned `dig-companion` binary and runs `dig-companion install`; the resolved plan/version is the install contract. |
| **dig-chrome-extension ↔ dig-node** | The extension's *server host* points at `localhost:8080`; it sends `dig.getContent` and **verifies + decrypts** the returned ciphertext locally (read-crypto is the same `dig_client` WASM the hub uses). |
| **dig-node → rpc.dig.net (upstream)** | On a cache miss / unhandled method, `dig-node` blind-fetches ciphertext + proof and relays passthrough methods over the same JSON-RPC read contract. |
| **dig-node ↔ digstore (`dig-node` crate)** | The read path **is** digstore's `dig_node::handle_rpc`, pinned to a digstore release tag — the same node the native DIG Browser runs in-process. One read path, one cache contract across the ecosystem. |
| **dig-node ↔ DIG Browser (native)** | Same wire contract and cache semantics; `dig-node` is the standalone-service form for users who run the extension in a normal browser rather than the native fork. |
| **DIG Browser "My Node" controller → dig-node** | The browser drives the `control.*` admin surface over loopback, reading the control token from `<config_dir>/control-token` and sending it as `X-Dig-Control-Token`. The contract (methods/params/results, `x-requires-auth`, error codes) is discoverable via `/openrpc.json` / `rpc.discover`. |
| **docs.dig.net** | The canonical dig-RPC param/result schemas are published by docs.dig.net; this node's `/openrpc.json` is the local method+error **discovery** surface that aligns with it. |

See the repo `README.md` for the full configuration table and `SYSTEM.md` (ecosystem root) for the
shared contracts and interaction map.
