// rpc.js — the companion's JSON-RPC 2.0 surface, mirroring the native dig-node's
// FFI method surface (digstore crates/dig-node `handle_rpc`):
//
//   dig.getContent       — local verified retrieval (blind fetch → verify → decrypt → cache)
//   dig.getCapsule       — alias of getContent at the capsule granularity
//   dig.getProof         — inclusion proof for a resource (served alongside content)
//   dig.getAnchoredRoot  — chain-anchored tip root (delegated to upstream)
//   cache.getConfig      — { cap_bytes, used_bytes }
//   cache.setCapBytes    — { cap_bytes } (floored at 64 MiB)
//   cache.clear          — {}
//
// Anything else falls through to a blind passthrough to the upstream, so the
// companion stays a correct transparent proxy for methods it does not resolve
// locally (e.g. dig.listCapsules, dig.getManifest, dig.getProofStatus).

const LOCAL_CONTENT_METHODS = new Set(["dig.getContent", "dig.getCapsule"]);
const CACHE_METHODS = new Set(["cache.getConfig", "cache.setCapBytes", "cache.clear"]);

/**
 * Classify a JSON-RPC method into how the companion handles it. PURE — no I/O —
 * so routing is unit-testable and is the single source of truth for dispatch.
 *
 * @param {string} method
 * @returns {"content"|"proof"|"anchoredRoot"|"cache"|"passthrough"}
 */
export function routeMethod(method) {
  if (LOCAL_CONTENT_METHODS.has(method)) return "content";
  if (method === "dig.getProof") return "proof";
  if (method === "dig.getAnchoredRoot") return "anchoredRoot";
  if (CACHE_METHODS.has(method)) return "cache";
  return "passthrough";
}

/** Build a JSON-RPC 2.0 success envelope. */
export function rpcResult(id, result) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

/** Build a JSON-RPC 2.0 error envelope. */
export function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

/**
 * Extract the URN-selection params a content/proof request carries. Accepts
 * either an explicit `urn` (preferred for the local node) OR the wire shape the
 * extension/native node use (`store_id` [+ `root`] [+ `resource`/`resource_key`]).
 * Returns a chia:// / urn:dig: string the node's getResource can parse, or null.
 *
 * PURE — unit-testable.
 * @param {object} params
 * @returns {string|null}
 */
export function urnFromParams(params) {
  if (!params || typeof params !== "object") return null;
  if (typeof params.urn === "string" && params.urn) return params.urn;
  const storeId = params.store_id || params.storeId;
  if (!storeId) return null;
  const root = params.root && params.root !== "latest" ? `:${params.root}` : "";
  const resource = params.resource || params.resource_key || params.resourceKey || "";
  const res = resource ? `/${resource}` : "";
  const salt = params.salt ? `?salt=${params.salt}` : "";
  return `urn:dig:chia:${storeId}${root}${res}${salt}`;
}

/**
 * Handle one JSON-RPC request object against the local node. Returns a JSON-RPC
 * 2.0 envelope (success or error). Never throws — errors are returned in-band.
 *
 * @param {import("./node.js").DigNode} node
 * @param {object} req a JSON-RPC 2.0 request { id, method, params }
 * @returns {Promise<object>}
 */
export async function handleRpc(node, req) {
  const id = req && "id" in req ? req.id : null;
  const method = req && typeof req.method === "string" ? req.method : "";
  const params = (req && req.params) || {};
  const route = routeMethod(method);

  try {
    switch (route) {
      case "content": {
        const urn = urnFromParams(params);
        if (!urn) return rpcError(id, -32602, "missing store_id / urn");
        const r = await node.getResource(urn);
        // base64 the decrypted bytes for JSON transport. The companion is local,
        // so returning plaintext to the (same-machine) client is legitimate —
        // it is the in-process-node equivalent.
        return rpcResult(id, {
          urn: r.urn,
          content_type: r.contentType,
          data: Buffer.from(r.bytes).toString("base64"),
          total_length: r.bytes.length,
          verified: r.verified,
          source: r.source,
          complete: true,
        });
      }
      case "proof": {
        const urn = urnFromParams(params);
        if (!urn) return rpcError(id, -32602, "missing store_id / urn");
        // The companion resolves content locally; expose the inclusion proof by
        // forwarding to the upstream (proof generation needs the served bytes /
        // tree, which only the host has). Blind passthrough.
        return node.proxyRaw({ jsonrpc: "2.0", id, method, params });
      }
      case "anchoredRoot": {
        const result = await node.getAnchoredRoot(params);
        return rpcResult(id, result);
      }
      case "cache": {
        if (method === "cache.getConfig") {
          return rpcResult(id, {
            cap_bytes: node.cache.capBytes,
            used_bytes: node.cache.usedBytes(),
          });
        }
        if (method === "cache.setCapBytes") {
          const cap = await node.cache.setCapBytes(params.cap_bytes);
          return rpcResult(id, { cap_bytes: cap });
        }
        // cache.clear
        await node.cache.clear();
        return rpcResult(id, {});
      }
      default: {
        // Passthrough: relay verbatim to the upstream (blind).
        return node.proxyRaw(req);
      }
    }
  } catch (e) {
    return rpcError(id, -32000, `dig-companion: ${e?.message || e}`);
  }
}
