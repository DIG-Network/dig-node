#!/usr/bin/env node
// dig-companion — the localhost companion server for the DIG Chrome extension.
//
// The extension resolves chia:// (DIG) content by calling the DIG RPC for encrypted, Merkle-proven
// chunks, then verifying + decrypting them CLIENT-SIDE. It can be pointed at a local RPC endpoint
// via its `server.host` setting; this server is that endpoint on localhost.
//
// v0 is a transparent, BLIND proxy: it forwards each DIG RPC request to the upstream
// (rpc.dig.net by default) and returns the response verbatim. It only ever relays ciphertext +
// proofs — verification and decryption happen in the extension against the on-chain root, never
// here. The roadmap (see README) is to embed a real local dig-node for offline / no-remote reads.
//
// Zero dependencies: Node 18+ built-in http server + global fetch.

import http from "node:http";

const PORT = Number(process.env.DIG_COMPANION_PORT || 8080);
const HOST = process.env.DIG_COMPANION_HOST || "127.0.0.1";
const UPSTREAM = (process.env.DIG_RPC_UPSTREAM || "https://rpc.dig.net").replace(/\/+$/, "");
const VERSION = "0.1.0";

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

// Forward a DIG RPC request to the upstream and relay the response verbatim (blind: ciphertext +
// proofs only; no inspection, no decryption).
async function proxyToUpstream(bodyBuf, contentType) {
  const upstream = await fetch(UPSTREAM, {
    method: "POST",
    headers: { "Content-Type": contentType || "application/json" },
    body: bodyBuf,
  });
  const buf = Buffer.from(await upstream.arrayBuffer());
  return { status: upstream.status, contentType: upstream.headers.get("content-type"), buf };
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
    sendJson(res, 200, { status: "ok", version: VERSION, upstream: UPSTREAM });
    return;
  }

  if (req.method === "POST") {
    try {
      const body = await readBody(req);
      const { status, contentType, buf } = await proxyToUpstream(body, req.headers["content-type"]);
      res.writeHead(status, {
        "Content-Type": contentType || "application/json",
        "Content-Length": buf.length,
      });
      res.end(buf);
    } catch (err) {
      // JSON-RPC-shaped error so the extension can surface it cleanly.
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

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(
    `dig-companion v${VERSION} listening on http://${HOST}:${PORT} → upstream ${UPSTREAM}\n` +
      `Point the DIG Chrome extension's "server host" at localhost:${PORT}.`
  );
});
