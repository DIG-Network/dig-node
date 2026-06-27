// Unit tests for the companion's pure parts: cache-key derivation, RPC routing,
// URN handling, and the on-disk LRU cache. Run with `node --test`.

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

import { cacheKey, DiskCache, CACHE_CAP_FLOOR } from "../src/cache.js";
import { routeMethod, urnFromParams, rpcResult, rpcError } from "../src/rpc.js";
import { parseURN, canonicalUrn, selectionFromParsed } from "../src/urn.js";

const STORE = "a".repeat(64);
const ROOT = "b".repeat(64);
const RK = "c".repeat(64);

// ---- cacheKey ---------------------------------------------------------------

test("cacheKey is deterministic for the same tuple", () => {
  assert.equal(cacheKey(STORE, ROOT, RK), cacheKey(STORE, ROOT, RK));
});

test("cacheKey is case-insensitive on its inputs", () => {
  assert.equal(cacheKey(STORE.toUpperCase(), ROOT, RK), cacheKey(STORE, ROOT, RK));
});

test("cacheKey distinguishes root (latest vs pinned)", () => {
  assert.notEqual(cacheKey(STORE, "latest", RK), cacheKey(STORE, ROOT, RK));
});

test("cacheKey distinguishes retrieval key (different resources)", () => {
  assert.notEqual(cacheKey(STORE, ROOT, RK), cacheKey(STORE, ROOT, "d".repeat(64)));
});

test("cacheKey is filesystem-safe (64 hex chars)", () => {
  assert.match(cacheKey(STORE, ROOT, RK), /^[0-9a-f]{64}$/);
});

// ---- routeMethod ------------------------------------------------------------

test("routeMethod classifies the local-node surface", () => {
  assert.equal(routeMethod("dig.getContent"), "content");
  assert.equal(routeMethod("dig.getCapsule"), "content");
  assert.equal(routeMethod("dig.getProof"), "proof");
  assert.equal(routeMethod("dig.getAnchoredRoot"), "anchoredRoot");
  assert.equal(routeMethod("cache.getConfig"), "cache");
  assert.equal(routeMethod("cache.setCapBytes"), "cache");
  assert.equal(routeMethod("cache.clear"), "cache");
});

test("routeMethod falls through unknown methods to passthrough", () => {
  assert.equal(routeMethod("dig.listCapsules"), "passthrough");
  assert.equal(routeMethod("dig.getManifest"), "passthrough");
  assert.equal(routeMethod("dig.getProofStatus"), "passthrough");
  assert.equal(routeMethod(""), "passthrough");
  assert.equal(routeMethod("totally.unknown"), "passthrough");
});

// ---- urnFromParams ----------------------------------------------------------

test("urnFromParams prefers an explicit urn", () => {
  assert.equal(urnFromParams({ urn: "chia://x" }), "chia://x");
});

test("urnFromParams builds from store_id + root + resource (wire shape)", () => {
  assert.equal(
    urnFromParams({ store_id: STORE, root: ROOT, resource: "index.html" }),
    `urn:dig:chia:${STORE}:${ROOT}/index.html`
  );
});

test("urnFromParams omits a 'latest' root", () => {
  assert.equal(
    urnFromParams({ store_id: STORE, root: "latest", resource_key: "app.js" }),
    `urn:dig:chia:${STORE}/app.js`
  );
});

test("urnFromParams appends a private-store salt", () => {
  assert.equal(
    urnFromParams({ store_id: STORE, salt: "ff" }),
    `urn:dig:chia:${STORE}?salt=ff`
  );
});

test("urnFromParams returns null without a store_id or urn", () => {
  assert.equal(urnFromParams({}), null);
  assert.equal(urnFromParams(null), null);
});

// ---- rpc envelope helpers ---------------------------------------------------

test("rpcResult/rpcError produce JSON-RPC 2.0 envelopes", () => {
  assert.deepEqual(rpcResult(7, { ok: 1 }), { jsonrpc: "2.0", id: 7, result: { ok: 1 } });
  assert.deepEqual(rpcError(7, -32000, "boom"), {
    jsonrpc: "2.0",
    id: 7,
    error: { code: -32000, message: "boom" },
  });
});

// ---- URN helpers (round-trip via the shared parser) -------------------------

test("parseURN + selectionFromParsed mirror the extension defaults", () => {
  const parsed = parseURN(`urn:dig:chia:${STORE}`);
  const sel = selectionFromParsed(parsed);
  assert.equal(sel.storeId, STORE);
  assert.equal(sel.root, "latest"); // rootless → latest
  assert.equal(sel.resourceKey, "index.html"); // default resource
  assert.equal(sel.salt, null);
});

test("canonicalUrn rebuilds a rooted resource URN", () => {
  const parsed = parseURN(`chia://urn:dig:chia:${STORE}:${ROOT}/app.js`);
  assert.equal(canonicalUrn(parsed), `urn:dig:chia:${STORE}:${ROOT}/app.js`);
});

// ---- DiskCache --------------------------------------------------------------

function tmpCacheDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "dig-companion-test-"));
}

test("DiskCache round-trips bytes + metadata", async () => {
  const dir = tmpCacheDir();
  const c = new DiskCache({ dir });
  const key = cacheKey(STORE, ROOT, RK);
  await c.put(key, Buffer.from("hello world"), { contentType: "text/plain", verified: true });
  const hit = await c.get(key);
  assert.ok(hit);
  assert.equal(hit.bytes.toString(), "hello world");
  assert.equal(hit.meta.contentType, "text/plain");
  assert.equal(hit.meta.verified, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("DiskCache returns null on a miss", async () => {
  const dir = tmpCacheDir();
  const c = new DiskCache({ dir });
  assert.equal(await c.get("deadbeef"), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("DiskCache.clear removes all entries", async () => {
  const dir = tmpCacheDir();
  const c = new DiskCache({ dir });
  const key = cacheKey(STORE, ROOT, RK);
  await c.put(key, Buffer.from("data"), { contentType: "text/plain" });
  assert.ok(await c.get(key));
  await c.clear();
  assert.equal(await c.get(key), null);
  assert.equal(c.usedBytes(), 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("DiskCache floors the cap at 64 MiB", async () => {
  const dir = tmpCacheDir();
  const c = new DiskCache({ dir, capBytes: 1 });
  assert.equal(c.capBytes, CACHE_CAP_FLOOR);
  const set = await c.setCapBytes(0);
  assert.equal(set, CACHE_CAP_FLOOR);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("DiskCache evicts least-recently-used over the cap", async () => {
  const dir = tmpCacheDir();
  // Cap at the 64 MiB floor; three 30 MiB entries (90 MiB) force one eviction.
  // NOTE: assert only on booleans here — never pass a multi-MiB Buffer into an
  // assertion that could fail, or the test runner's failure-diff would try to
  // serialize it and blow the heap.
  const c = new DiskCache({ dir, capBytes: CACHE_CAP_FLOOR });
  const big = 30 * 1024 * 1024; // 30 MiB each
  const k1 = "1".repeat(64);
  const k2 = "2".repeat(64);
  const k3 = "3".repeat(64);
  await c.put(k1, Buffer.alloc(big, 1), { contentType: "x" });
  await new Promise((r) => setTimeout(r, 10));
  await c.put(k2, Buffer.alloc(big, 2), { contentType: "x" });
  await new Promise((r) => setTimeout(r, 10));
  await c.get(k1); // bump k1 recency → k2 is now the LRU victim
  await new Promise((r) => setTimeout(r, 10));
  await c.put(k3, Buffer.alloc(big, 3), { contentType: "x" }); // 90 MiB > 64 MiB → evict LRU

  assert.ok(c.usedBytes() <= c.capBytes, "used must be within cap after eviction");
  assert.equal((await c.get(k2)) === null, true, "k2 (LRU) should be evicted");
  assert.equal((await c.get(k3)) !== null, true, "k3 (just added) should remain");
  fs.rmSync(dir, { recursive: true, force: true });
});
