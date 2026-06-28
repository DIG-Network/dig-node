#!/usr/bin/env node
// dig-companion — the localhost companion server for the DIG Chrome extension.
//
// The extension resolves chia:// (DIG) content by calling a DIG RPC for encrypted,
// Merkle-proven chunks. It can be pointed at a LOCAL RPC endpoint via its
// `server.host` setting; this server is that endpoint on localhost.
//
// Beyond a blind proxy, the companion now embeds a LOCAL dig-node (src/node.js):
// it blind-fetches ciphertext + Merkle proof from the upstream, then VERIFIES
// inclusion against the anchored root and DECRYPTS locally — using the SAME
// dig_client read-crypto WASM the extension uses — and caches the result on disk.
// This is the standalone-server twin of the native DIG Browser's in-process
// dig-node. A LOCAL companion legitimately decrypts (it is the user's own
// machine, like the in-process node); the "blind host" property only constrains
// REMOTE hosts.
//
// JSON-RPC surface (mirrors the native dig-node FFI — see src/rpc.js):
//   dig.getContent / dig.getCapsule  — local verified retrieval (+ cache)
//   dig.getProof                     — inclusion proof (forwarded to upstream)
//   dig.getAnchoredRoot              — chain-anchored tip root (forwarded)
//   cache.getConfig / setCapBytes / clear
//   anything else                    — blind passthrough to the upstream
//
// Zero runtime dependencies: Node 18+ built-in http server + global fetch +
// WebAssembly. The only "asset" is the vendored dig_client WASM (see
// src/vendor/PROVENANCE.md), SRI-verified at startup.

import http from "node:http";
import { DigNode } from "./node.js";
import { DiskCache, defaultCacheDir } from "./cache.js";
import { handleRpc } from "./rpc.js";

const PORT = Number(process.env.DIG_COMPANION_PORT || 8080);
const HOST = process.env.DIG_COMPANION_HOST || "127.0.0.1";
const UPSTREAM = (process.env.DIG_RPC_UPSTREAM || "https://rpc.dig.net").replace(/\/+$/, "");
const CACHE_DIR = defaultCacheDir();
const CACHE_CAP = process.env.DIG_COMPANION_CACHE_CAP_BYTES
  ? Number(process.env.DIG_COMPANION_CACHE_CAP_BYTES)
  : undefined;
const VERSION = "0.2.0";

// Shared local node + cache for the process lifetime.
const cache = new DiskCache({ dir: CACHE_DIR, capBytes: CACHE_CAP });
const node = new DigNode({ upstream: UPSTREAM, cache });

// The extension calls from a chrome-extension:// origin; allow it (and any localhost dev origin).
function setCors(res, origin) {
  const allow =
    origin && (origin.startsWith("chrome-extension://") || origin.startsWith("http://localhost"))
      ? origin
      : "*";
  res.setHeader("Access-Control-Allow-Origin", allow);
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
}

function sendJson(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": payload.length });
  res.end(payload);
}

async function readBody(req, limitBytes = 8 * 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limitBytes) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  setCors(res, origin);

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    sendJson(res, 200, {
      status: "ok",
      version: VERSION,
      upstream: UPSTREAM,
      mode: "local-node",
      cache: { dir: CACHE_DIR, cap_bytes: cache.capBytes, used_bytes: cache.usedBytes() },
    });
    return;
  }

  if (req.method === "POST") {
    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      sendJson(res, 413, {
        jsonrpc: "2.0",
        error: { code: -32010, message: `dig-companion: ${err?.message || err}` },
        id: null,
      });
      return;
    }

    // Parse the JSON-RPC request. If it isn't valid JSON, fall back to a blind
    // passthrough of the raw bytes (keeps the v0 transparent-proxy behaviour for
    // any non-JSON or oddly-shaped payload).
    let reqObj;
    try {
      reqObj = JSON.parse(body.toString("utf8"));
    } catch {
      reqObj = null;
    }

    try {
      if (reqObj && typeof reqObj === "object" && !Array.isArray(reqObj)) {
        const out = await handleRpc(node, reqObj);
        sendJson(res, 200, out);
        return;
      }
      // Batch requests or non-object bodies: blind passthrough to the upstream.
      const out = await node.proxyRaw(reqObj ?? JSON.parse(body.toString("utf8")));
      sendJson(res, 200, out);
    } catch (err) {
      sendJson(res, 502, {
        jsonrpc: "2.0",
        error: { code: -32010, message: `dig-companion upstream error: ${err?.message || err}` },
        id: null,
      });
    }
    return;
  }

  sendJson(res, 405, { error: "method not allowed" });
});

// Only start listening when run directly (not when imported by tests).
import { fileURLToPath } from "node:url";
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  server.listen(PORT, HOST, () => {
    // eslint-disable-next-line no-console
    console.log(
      `dig-companion v${VERSION} (local-node) listening on http://${HOST}:${PORT}\n` +
        `  upstream:  ${UPSTREAM}\n` +
        `  cache dir: ${CACHE_DIR} (cap ${cache.capBytes} bytes)\n` +
        `Point the DIG Chrome extension's "server host" at localhost:${PORT}.`
    );
  });
}

export { server, node, cache };
