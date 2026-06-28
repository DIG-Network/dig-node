// Tests for the vendored dig_client WASM loader: it must SRI-verify and expose
// the read-crypto functions, computing values identical to the extension's.

import { test } from "node:test";
import assert from "node:assert/strict";
import { ensureDig, DIG_CLIENT_WASM_SHA256 } from "../src/dig-client.js";

test("ensureDig loads the SRI-verified WASM and exposes read-crypto", async () => {
  const dig = await ensureDig();
  assert.equal(typeof dig.retrievalKey, "function");
  assert.equal(typeof dig.deriveKey, "function");
  assert.equal(typeof dig.verifyInclusion, "function");
  assert.equal(typeof dig.decryptChunk, "function");
});

test("retrievalKey is deterministic 64-hex (matches the wasm read path)", async () => {
  const dig = await ensureDig();
  const rk = dig.retrievalKey("a".repeat(64), "index.html");
  assert.match(rk, /^[0-9a-f]{64}$/);
  // Stable value (also produced by the extension's vendored WASM) — locks the
  // contract so a WASM swap that changed the key derivation would fail here.
  assert.equal(rk, "bc3a8800bcb212783bfe4ab1a3ce55e2d14fc14ca119ba00fa7ba44ae2a8de06");
});

test("deriveKey is deterministic 64-hex", async () => {
  const dig = await ensureDig();
  const key = dig.deriveKey("a".repeat(64), "index.html", null);
  assert.match(key, /^[0-9a-f]{64}$/);
  assert.equal(key, "2ffaf4b0be5609d67400ac07a921d85be22fef983e3e0fd355679b3a0051656d");
});

test("the SRI constant is the canonical ecosystem digest", () => {
  assert.equal(
    DIG_CLIENT_WASM_SHA256,
    "ff486be806f908a2a90780e499a04dbd34e10e3b97be0470cb9ee841a1e49e77"
  );
});
