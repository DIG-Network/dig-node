// Integration tests for the RPC router against a mock upstream DIG RPC.
// Exercises cache.* config methods, getAnchoredRoot delegation, and blind
// passthrough — without touching the network or rpc.dig.net.
//
// NOTE: each test owns its own mock upstream (no shared before/after hook). Some
// Node 20.x releases run a top-level `before()` AFTER the tests, which would
// leave the upstream URL undefined and silently fall back to the real
// rpc.dig.net — so setup is done per-test for version independence.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

import { DigNode } from "../src/node.js";
import { DiskCache, CACHE_CAP_FLOOR } from "../src/cache.js";
import { handleRpc } from "../src/rpc.js";

/**
 * Start a mock upstream DIG RPC. Returns { url, calls, close }. `calls` records
 * every request object the upstream received (for asserting what was relayed).
 */
async function startMockUpstream() {
  const calls = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const reqObj = JSON.parse(Buffer.concat(chunks).toString());
      calls.push(reqObj);
      let result;
      if (reqObj.method === "dig.getAnchoredRoot") {
        result = { store_id: reqObj.params.store_id, root: "f".repeat(64) };
      } else if (reqObj.method === "dig.listCapsules") {
        result = { capsules: ["passthrough-ok"] };
      } else {
        result = { echoed: reqObj.method };
      }
      const body = JSON.stringify({ jsonrpc: "2.0", id: reqObj.id, result });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    calls,
    close: () => new Promise((r) => server.close(r)),
  };
}

/** A fresh node + temp cache pointed at the given upstream URL. */
function freshNode(upstreamUrl) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dig-companion-rpc-"));
  const cache = new DiskCache({ dir });
  return {
    node: new DigNode({ upstream: upstreamUrl, cache }),
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

test("cache.getConfig reports cap + used bytes", async () => {
  const up = await startMockUpstream();
  const { node, cleanup } = freshNode(up.url);
  try {
    const out = await handleRpc(node, { jsonrpc: "2.0", id: 1, method: "cache.getConfig" });
    assert.equal(out.result.used_bytes, 0);
    assert.ok(out.result.cap_bytes >= CACHE_CAP_FLOOR);
  } finally {
    cleanup();
    await up.close();
  }
});

test("cache.setCapBytes floors at 64 MiB and is reflected by getConfig", async () => {
  const up = await startMockUpstream();
  const { node, cleanup } = freshNode(up.url);
  try {
    const set = await handleRpc(node, {
      jsonrpc: "2.0",
      id: 2,
      method: "cache.setCapBytes",
      params: { cap_bytes: 1 },
    });
    assert.equal(set.result.cap_bytes, CACHE_CAP_FLOOR);
    const cfg = await handleRpc(node, { jsonrpc: "2.0", id: 3, method: "cache.getConfig" });
    assert.equal(cfg.result.cap_bytes, CACHE_CAP_FLOOR);
  } finally {
    cleanup();
    await up.close();
  }
});

test("cache.clear returns an empty result", async () => {
  const up = await startMockUpstream();
  const { node, cleanup } = freshNode(up.url);
  try {
    const out = await handleRpc(node, { jsonrpc: "2.0", id: 4, method: "cache.clear" });
    assert.deepEqual(out.result, {});
  } finally {
    cleanup();
    await up.close();
  }
});

test("dig.getAnchoredRoot delegates to the upstream and unwraps the result", async () => {
  const up = await startMockUpstream();
  const { node, cleanup } = freshNode(up.url);
  try {
    const out = await handleRpc(node, {
      jsonrpc: "2.0",
      id: 5,
      method: "dig.getAnchoredRoot",
      params: { store_id: "a".repeat(64) },
    });
    assert.equal(out.result.root, "f".repeat(64));
    assert.equal(out.result.store_id, "a".repeat(64));
    assert.equal(up.calls.length, 1);
    assert.equal(up.calls[0].method, "dig.getAnchoredRoot");
  } finally {
    cleanup();
    await up.close();
  }
});

test("unknown methods are blind-passthrough relayed to the upstream", async () => {
  const up = await startMockUpstream();
  const { node, cleanup } = freshNode(up.url);
  try {
    const out = await handleRpc(node, {
      jsonrpc: "2.0",
      id: 6,
      method: "dig.listCapsules",
      params: {},
    });
    assert.deepEqual(out.result, { capsules: ["passthrough-ok"] });
    assert.equal(up.calls[0].method, "dig.listCapsules");
  } finally {
    cleanup();
    await up.close();
  }
});

test("dig.getContent without store_id/urn returns an invalid-params error", async () => {
  const up = await startMockUpstream();
  const { node, cleanup } = freshNode(up.url);
  try {
    const out = await handleRpc(node, {
      jsonrpc: "2.0",
      id: 7,
      method: "dig.getContent",
      params: {},
    });
    assert.equal(out.error.code, -32602);
    // Must NOT have reached the upstream — local validation rejects it first.
    assert.equal(up.calls.length, 0);
  } finally {
    cleanup();
    await up.close();
  }
});
