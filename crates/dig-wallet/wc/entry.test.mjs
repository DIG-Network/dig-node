// Unit tests for the WalletConnect responder's request shaping — the one piece
// of Task A that is testable without a live relay. Run with:
//
//   cd crates/dig-wallet/wc && node --test
//
// (CI does not run these — the crate is offline-built — but they guard the
// session_request → /api/wc/request routing so a regression is caught locally.)
//
// They load the SOURCE signer bridge (not the minified bundle) so the test maps
// to readable code; the bundle includes the same module, just packed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { callLocalSigner } from "./signer.js";

test("callLocalSigner POSTs {method,params} to the loopback signer", async () => {
  let captured;
  const fakeFetch = async (url, opts) => {
    captured = { url, method: opts.method, body: JSON.parse(opts.body) };
    return { ok: true, status: 200, json: async () => ({ data: { address: "xch1abc" } }) };
  };
  const out = await callLocalSigner("chia_getAddress", { foo: 1 }, fakeFetch);
  assert.equal(captured.url, "/api/wc/request");
  assert.equal(captured.method, "POST");
  assert.equal(captured.body.method, "chia_getAddress");
  assert.deepEqual(captured.body.params, { foo: 1 });
  // Unwraps the signer's bare `data` (what Sage would return for the method).
  assert.deepEqual(out, { address: "xch1abc" });
});

test("callLocalSigner defaults missing params to {}", async () => {
  let captured;
  const fakeFetch = async (_url, opts) => {
    captured = JSON.parse(opts.body);
    return { ok: true, status: 200, json: async () => ({ data: true }) };
  };
  await callLocalSigner("chip0002_chainId", undefined, fakeFetch);
  assert.deepEqual(captured.params, {});
});

test("callLocalSigner throws on a signer error (consent/broadcast gate)", async () => {
  const errFetch = async () => ({
    ok: false,
    status: 403,
    json: async () => ({ error: "origin not connected" }),
  });
  await assert.rejects(
    () => callLocalSigner("chip0002_signMessage", {}, errFetch),
    /origin not connected/
  );
});

test("callLocalSigner throws on an error body even with 200", async () => {
  const errFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ error: "wallet is locked" }),
  });
  await assert.rejects(
    () => callLocalSigner("chip0002_getPublicKeys", {}, errFetch),
    /wallet is locked/
  );
});
