# dig-companion

The **localhost companion server** for the [DIG Chrome extension](https://github.com/DIG-Network/dig-chrome-extension).

The extension resolves `chia://` (DIG) URLs by fetching encrypted, Merkle-proven content over a
DIG RPC. By default it talks to `rpc.dig.net`, but it can be pointed at a **local** RPC endpoint via
its `server.host` setting. `dig-companion` is that local endpoint — and as of v0.2 it is a real
**local DIG node**, not just a proxy.

It is the standalone-server twin of the native [DIG Browser](https://github.com/DIG-Network/DIG_Browser)'s
**in-process dig-node**: the same blind-retrieval-then-local-verify/decrypt read path, packaged as a
companion app for the extension on non-DIG browsers.

> A **local** companion legitimately verifies and decrypts content — it is the user's own machine,
> exactly like the native browser's in-process dig-node. The "blind host" property only constrains
> **remote** hosts (`rpc.dig.net` / `cdn.dig.net`), which still only ever see ciphertext + proofs.

## What it does

It runs a small HTTP server on `127.0.0.1` (default port `8080`) exposing two things:

1. **A local DIG node** that resolves content on your machine:
   - blind-fetches ciphertext + a Merkle inclusion proof from the upstream,
   - **verifies** inclusion against the anchored root,
   - **decrypts** locally (AES-256-GCM-SIV) using the **same `dig_client` read-crypto WASM** the
     extension uses (vendored — see [`src/vendor/PROVENANCE.md`](src/vendor/PROVENANCE.md), SRI-verified
     at startup, fails closed on mismatch),
   - **caches** the decrypted resource on disk and serves it from cache on repeat.

2. **`GET /health`** — `{ status, version, upstream, mode, cache }` liveness probe.

CORS allows `chrome-extension://` origins so the extension can call it.

### JSON-RPC surface

`POST /` speaks JSON-RPC 2.0, mirroring the native dig-node's FFI method surface
(`dig::CallDigRpc` in digstore `crates/dig-node`):

| Method | Behaviour |
|---|---|
| `dig.getContent` / `dig.getCapsule` | **Local verified retrieval**: fetch → verify → decrypt → cache. Returns `{ urn, content_type, data (base64 plaintext), total_length, verified, source, complete }`. `source` is `local` (cache hit) or `remote` (freshly fetched). |
| `dig.getProof` | Inclusion proof for a resource — forwarded to the upstream (proof generation needs the host's tree). |
| `dig.getAnchoredRoot` | Store's chain-anchored tip root — forwarded to the upstream (the companion has no chain client of its own; the native node resolves this directly from coinset.org). |
| `cache.getConfig` | `{ cap_bytes, used_bytes }`. |
| `cache.setCapBytes` | `{ cap_bytes }` (floored at 64 MiB, same as the native node). |
| `cache.clear` | `{}` — drops all cached resources. |
| *anything else* | **Blind passthrough** to the upstream (e.g. `dig.listCapsules`, `dig.getManifest`), so the companion stays a correct transparent proxy for methods it does not resolve locally. |

Request params for content methods accept either an explicit `urn` (a `chia://` / `urn:dig:`
string) **or** the wire shape the extension/native node use: `store_id` [+ `root`] [+
`resource`/`resource_key`] [+ `salt`].

## Run

```bash
# Node 18+ (uses the built-in fetch + http server + WebAssembly — zero runtime dependencies)
node src/server.js
# or
npm start

# custom port / upstream / cache
DIG_COMPANION_PORT=8080 DIG_RPC_UPSTREAM=https://rpc.dig.net node src/server.js
```

## Point the extension at it

In the DIG Chrome extension's options, set **server host** to:

```
localhost:8080
```

(The extension defaults to `localhost:80`; port 80 needs elevated privileges on most OSes, so the
companion defaults to `8080` — set the extension to match, or run the companion on `80` if you can.)

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `DIG_COMPANION_PORT` | `8080` | Port the companion listens on (`127.0.0.1`). |
| `DIG_COMPANION_HOST` | `127.0.0.1` | Bind address. |
| `DIG_RPC_UPSTREAM` | `https://rpc.dig.net` | Upstream DIG RPC the node blind-fetches ciphertext/proofs from and passes unhandled methods through to. |
| `DIG_COMPANION_CACHE_DIR` | `<tmp>/dig-companion-cache` | Disk cache directory. |
| `DIG_COMPANION_CACHE_CAP_BYTES` | `512 MiB` | Cache size cap (floored at 64 MiB). LRU eviction keeps usage under the cap. |

## Cache

Resolved resources are cached on disk keyed by `storeId:root:retrievalKey` (a rootless "latest"
URN and a pinned-root URN are distinct entries, because "latest" can move). Each entry is the
**decrypted** bytes plus small metadata. The cache is LRU-evicted to stay under the cap and can be
cleared via the `cache.clear` RPC. (Unlike the native node, which caches whole compiled `.dig`
*modules* keyed by capsule, the companion caches per-*resource* blobs — the granularity the
extension read path produces. The `cache.*` config contract is identical.)

## Tests

```bash
npm test          # node --test test/
```

Covers the pure parts (cache-key derivation, RPC routing, URN handling), the LRU disk cache, the
SRI-verified WASM loader (read-crypto values locked to the canonical digest), the RPC router against
a mock upstream, and a server `/health` + CORS + cache-RPC smoke test.

## Architecture

```
src/
  server.js     HTTP server: /health, CORS, routes POST → handleRpc, proxy fallback
  rpc.js        JSON-RPC router (pure routeMethod + urnFromParams; handleRpc dispatch)
  node.js       DigNode — local verified retrieval (fetch → verify → decrypt → cache) + getAnchoredRoot
  cache.js      DiskCache — LRU disk cache keyed by storeId:root:retrievalKey (+ pure cacheKey)
  dig-client.js Node loader for the vendored read-crypto WASM (SRI-verified, fail-closed)
  urn.js        parseURN (shared parser) + canonical URN / selection helpers
  vendor/       vendored dig_client WASM + shared URN parser (see PROVENANCE.md)
```

## Relationship to the rest of the ecosystem

- The read path (URN → retrieval key → ciphertext + proof → verify → decrypt) is byte-identical to
  the extension's `fetchContentViaRPC` and the hub's `dig-client`. The companion vendors the same
  `dig_client` WASM artifact and asserts the same SHA-256 (see `SYSTEM.md`).
- It mirrors the native dig-node's `dig.getContent` / `dig.getAnchoredRoot` / `cache.*` method
  surface so clients see one consistent local-node API across the extension and the native browser.

## Remaining gaps (vs. the native in-process dig-node)

- **Anchored-root + proof are delegated to the upstream**, not resolved on-chain locally. The native
  node walks the DataStore singleton lineage on coinset.org for `dig.getAnchoredRoot` and generates
  proofs from its local tree; the companion has no chain/§21 client of its own yet, so it forwards
  those. This means rootless ("latest") URN root-pinning still trusts the upstream's reported root.
- **No §21 authenticated whole-store sync.** The native node can clone/sync a whole `.dig` module and
  serve it fully offline; the companion fetches per-resource ciphertext on a cache miss (then serves
  locally from cache thereafter), so a cold resource still needs the upstream.
- Caching granularity is per-resource, not per-module/capsule.

## License

See the DIG Network organization.
