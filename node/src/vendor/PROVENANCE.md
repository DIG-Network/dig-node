# Vendored artifacts — provenance

These files are vendored copies of the DIG read-crypto WASM and the shared URN parser.
They are byte-identical to the artifacts shipped by the `dig-chrome-extension` (which
in turn re-exports the `dig_client` WASM built from `chip35_dl_coin`). Vendoring them
lets the companion run the **same** verify/decrypt read path the extension uses, in-process,
with no network round-trip for the crypto.

| File | Source (in this monorepo) | Notes |
|---|---|---|
| `dig_client.mjs` | `modules/dig-chrome-extension/dig_client.js` | wasm-bindgen ES-module glue. Copied verbatim, renamed `.js` → `.mjs` so Node loads it as an ES module (the companion package is `"type": "module"`; the extension package is not). No code changes. |
| `dig_client_bg.wasm` | `modules/dig-chrome-extension/dig_client_bg.wasm` | The read-crypto WASM binary. Copied verbatim. |
| `dig-urn.mjs` | `modules/dig-chrome-extension/dig-urn.mjs` | The single shared URN parser (already an ES module). Copied verbatim. |

## Subresource Integrity (SRI)

`dig_client_bg.wasm` SHA-256 (lowercase hex):

```
ff486be806f908a2a90780e499a04dbd34e10e3b97be0470cb9ee841a1e49e77
```

This is the **same digest** asserted by:

- `dig-chrome-extension/background.js` → `DIG_CLIENT_WASM_SHA256`
- `hub.dig.net` `sw.js` and `apps/web/lib/dig-client.js`

The companion's loader (`src/dig-client.js`) re-verifies this digest at startup and
**fails closed** if it does not match — a tampered or wrong WASM refuses to run unverified
crypto, exactly as the extension does.

## Updating

If the canonical `dig_client` WASM changes (new `chip35_dl_coin` release → extension bump),
re-copy all three files from `modules/dig-chrome-extension/`, recompute the SHA-256 of
`dig_client_bg.wasm`, and update the `DIG_CLIENT_WASM_SHA256` constant in `src/dig-client.js`
**and** the digest above. Keep this digest in lock-step with the extension/hub.
