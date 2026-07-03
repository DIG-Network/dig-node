// Bridge from the WalletConnect responder to the native loopback signer.
//
// Kept in its own module (no @walletconnect import) so the session_request →
// `/api/wc/request` routing is unit-testable in plain Node without pulling in
// the relay client or browser globals. `entry.js` imports `callLocalSigner`.

// JSON-RPC "method not found" (per WC / EIP-1474), used when the signer rejects.
export const METHOD_NOT_FOUND = -32601;

/**
 * POST {method, params} to the native loopback signer and unwrap its reply.
 *
 * This is the single bridge between a dapp's WC `session_request` and the Rust
 * `wc_dispatch`: the body is byte-for-byte what the injected `window.chia`
 * provider sends, so the SAME per-origin consent + DIG_WALLET_ALLOW_BROADCAST
 * gates apply. Returns the bare result `data` (what Sage returns for the method);
 * throws on any signer error (locked wallet, unapproved origin, unsupported
 * method, broadcast disabled).
 *
 * `fetchImpl` is injectable for tests; defaults to the page `fetch`.
 */
export async function callLocalSigner(method, params, fetchImpl) {
  const f = fetchImpl || fetch;
  const r = await f("/api/wc/request", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ method, params: params || {} }),
  });
  let body = {};
  try {
    body = await r.json();
  } catch (e) {
    /* non-JSON error body */
  }
  if (!r.ok || body.error) {
    throw new Error(body.error || `signer error (${r.status})`);
  }
  return body.data;
}
