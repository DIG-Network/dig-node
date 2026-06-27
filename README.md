# dig-companion

The **localhost companion server** for the [DIG Chrome extension](https://github.com/DIG-Network/dig-chrome-extension).

The extension resolves `chia://` (DIG) URLs by fetching encrypted, Merkle-proven content over the
DIG RPC, then verifying + decrypting it **client-side** (its WASM does the crypto). By default it
talks to `rpc.dig.net`, but it can be pointed at a **local** RPC endpoint via its `server.host`
setting. `dig-companion` is that local endpoint: a small server on `localhost` that speaks the DIG
RPC so the browser can resolve and serve DIG content through your own machine.

It is the standalone-server twin of the native [DIG Browser](https://github.com/DIG-Network/DIG_Browser)'s
**in-process dig-node** and of `digstore serve` — same §21 blind-retrieval read path, packaged as a
companion app for the extension.

> Status: **pre-release scaffold.** v0 is a transparent localhost proxy to `rpc.dig.net` (works
> today). The roadmap is to embed a real local **dig-node** (offline cache + blind retrieval) so the
> companion serves DIG content without round-tripping a remote.

## What it does

- Listens on `127.0.0.1` (default port `8080`).
- `POST /` — the DIG JSON-RPC surface the extension calls (`dig.getContent`, `dig.getCapsule`,
  `dig.getProof`, …). v0 forwards each request to `rpc.dig.net` and returns the response verbatim,
  so the extension's client-side verify + decrypt is unchanged (the companion never sees plaintext
  or keys — it relays ciphertext + proofs only).
- `GET /health` — `{ "status": "ok", "version": "…" }` liveness probe.
- CORS allows `chrome-extension://` origins so the extension can call it.

The companion is **blind** by design: it relays ciphertext + Merkle proofs. Verification and
decryption happen in the extension (or browser) against the on-chain root — never here.

## Run

```bash
# Node 18+ (uses the built-in fetch + http server — zero dependencies)
node src/server.js
# or
npm start

# custom port / upstream
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
| `DIG_RPC_UPSTREAM` | `https://rpc.dig.net` | Upstream DIG RPC the v0 proxy forwards to. |

## Roadmap

1. **v0 (this scaffold):** transparent localhost proxy to `rpc.dig.net`.
2. **Local dig-node:** embed the `digstore` dig-node (blind retrieval + a local content cache) so the
   companion resolves `dig://` without a remote round-trip — the same FFI read path
   (`dig.getAnchoredRoot` / `dig.getContent`) the native DIG Browser links in-process.
3. **Auto-launch + health UX:** a tray/companion launcher the extension can detect, with a clear
   "companion not running" affordance in the popup.

## License

See the DIG Network organization.
