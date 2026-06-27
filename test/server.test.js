// Server smoke test: the HTTP server starts, /health responds, CORS preflight
// works, and an unhandled JSON-RPC method is relayed (here, against the real
// default upstream path the server is wired to — we only assert the server
// itself responds with a well-formed envelope, not the upstream's content).
//
// Importing server.js does NOT auto-listen (it guards on isMain), so we drive
// the exported `server` on an ephemeral port.

import { test } from "node:test";
import assert from "node:assert/strict";
import { server } from "../src/server.js";

async function withServer(fn) {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test("GET /health returns ok + local-node mode + cache info", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const j = await res.json();
    assert.equal(j.status, "ok");
    assert.equal(j.mode, "local-node");
    assert.ok(j.version);
    assert.ok(j.cache && typeof j.cache.cap_bytes === "number");
  });
});

test("OPTIONS preflight returns CORS headers (204)", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/`, {
      method: "OPTIONS",
      headers: { Origin: "chrome-extension://abcdef", "Access-Control-Request-Method": "POST" },
    });
    assert.equal(res.status, 204);
    assert.equal(res.headers.get("access-control-allow-origin"), "chrome-extension://abcdef");
    assert.match(res.headers.get("access-control-allow-methods") || "", /POST/);
  });
});

test("cache.* JSON-RPC is handled locally by the running server", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "cache.getConfig" }),
    });
    assert.equal(res.status, 200);
    const j = await res.json();
    assert.equal(j.jsonrpc, "2.0");
    assert.ok(j.result && typeof j.result.cap_bytes === "number");
    assert.ok(typeof j.result.used_bytes === "number");
  });
});
