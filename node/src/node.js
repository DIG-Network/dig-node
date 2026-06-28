// node.js — the companion's LOCAL dig-node.
//
// This is the in-process port of the native DIG Browser's dig-node read path
// (digstore crates/dig-node `handle_rpc`) and of the extension's
// fetchContentViaRPC pipeline. It does BLIND retrieval from the upstream
// (ciphertext + Merkle proof), then LOCAL verify + decrypt + cache — so the
// extension pointed at this companion gets a real local resolver, not just a
// proxy.
//
// Read pipeline (mirrors dig-chrome-extension/background.js fetchContentViaRPC):
//   1. parse URN → storeId, root, resourceKey, salt
//   2. retrievalKey = SHA256(canonical rootless URN)   [wasm]
//   3. fetch ciphertext (chunked 3-MiB windows) + inclusion proof from upstream
//   4. verifyInclusion(ciphertext, proof, root)        [wasm] — decoys → false
//   5. deriveKey(storeId, resourceKey, salt)           [wasm]
//   6. decryptChunk(s)                                 [wasm] — GCM-SIV
//   7. cache the decrypted bytes locally; serve from cache on repeat

import { ensureDig } from "./dig-client.js";
import { parseURN, canonicalUrn, selectionFromParsed } from "./urn.js";
import { DiskCache, cacheKey } from "./cache.js";

// RPC back-end caps each window at 3 MiB; loop until `complete` (same as the
// extension's RPC_CHUNK).
const RPC_CHUNK = 3 * 1024 * 1024;

/** Infer a MIME type from a resource key extension (ported from background.js ctForPath). */
export function ctForPath(resourceKey) {
  const ext = (String(resourceKey).split(".").pop() || "").toLowerCase();
  return (
    {
      html: "text/html; charset=utf-8",
      htm: "text/html; charset=utf-8",
      js: "text/javascript; charset=utf-8",
      mjs: "text/javascript; charset=utf-8",
      css: "text/css; charset=utf-8",
      json: "application/json",
      png: "image/png",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      gif: "image/gif",
      svg: "image/svg+xml",
      webp: "image/webp",
      ico: "image/x-icon",
      woff: "font/woff",
      woff2: "font/woff2",
      txt: "text/plain",
      pdf: "application/pdf",
      mp4: "video/mp4",
      webm: "video/webm",
      wasm: "application/wasm",
      xml: "application/xml",
      md: "text/markdown",
    }[ext] || "application/octet-stream"
  );
}

/**
 * Decrypt multi-chunk ciphertext (ported from background.js decryptChunks).
 * `chunkLens` are the per-chunk CIPHERTEXT byte lengths (may be null/empty for a
 * single-chunk resource).
 */
function decryptChunks(dig, keyHex, ciphertext, chunkLens) {
  const lens = chunkLens && chunkLens.length ? chunkLens : [ciphertext.length];
  if (lens.length === 1) return dig.decryptChunk(keyHex, ciphertext); // fast path
  const lensSum = lens.reduce((a, n) => a + n, 0);
  if (lensSum !== ciphertext.length) {
    throw new Error("served ciphertext length does not match chunk lengths");
  }
  const parts = [];
  let p = 0;
  for (const len of lens) {
    parts.push(dig.decryptChunk(keyHex, ciphertext.subarray(p, p + len)));
    p += len;
  }
  const total = parts.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(total);
  let q = 0;
  for (const part of parts) {
    out.set(part, q);
    q += part.length;
  }
  return out;
}

/**
 * The local DIG node. Owns the upstream client, the disk cache, and the WASM
 * read-crypto. Construct once and reuse.
 */
export class DigNode {
  /**
   * @param {{ upstream: string, cache?: DiskCache }} opts
   */
  constructor(opts) {
    this.upstream = String(opts.upstream || "https://rpc.dig.net").replace(/\/+$/, "");
    this.cache = opts.cache || new DiskCache();
  }

  /** One JSON-RPC 2.0 POST to the upstream. Throws on transport / RPC error. */
  async _rpc(method, params) {
    let res;
    try {
      res = await fetch(this.upstream, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
    } catch {
      throw new Error("could not reach the upstream DIG RPC");
    }
    if (!res.ok) throw new Error(`upstream RPC HTTP ${res.status}`);
    const j = await res.json();
    if (j && j.error) {
      throw new Error(`upstream ${method}: ${j.error.message || "error"}`);
    }
    return j ? j.result : null;
  }

  /**
   * Fetch the full ciphertext for a resource from the upstream, reassembling
   * 3-MiB windows (ported from background.js fetchVerified). Returns
   * { ciphertext: Buffer, proof: string, chunkLens: number[]|null }.
   */
  async _fetchCiphertext(storeId, rk, root) {
    let offset = 0;
    let total = null;
    let buf = null;
    let proof = "";
    let chunkLens = null;

    for (;;) {
      const r = await this._rpc("dig.getContent", {
        store_id: storeId,
        root,
        retrieval_key: rk,
        offset,
        length: RPC_CHUNK,
      });
      if (!r) throw new Error("upstream returned no data");
      if (total === null) {
        total = r.total_length >>> 0;
        buf = Buffer.alloc(total);
      }
      if (chunkLens === null && Array.isArray(r.chunk_lens)) {
        chunkLens = r.chunk_lens.map((n) => n >>> 0);
      }
      const chunk = Buffer.from(r.ciphertext || "", "base64");
      const at = r.offset >>> 0;
      const copyLen = Math.max(0, Math.min(chunk.length, total - at));
      chunk.copy(buf, at, 0, copyLen);
      if (r.inclusion_proof) proof = r.inclusion_proof;
      if (r.complete || r.next_offset == null) break;
      offset = r.next_offset >>> 0;
    }
    return { ciphertext: buf, proof, chunkLens };
  }

  /**
   * `dig.getAnchoredRoot`: resolve a store's chain-anchored tip root. The
   * companion has no chain client of its own, so it forwards to the upstream —
   * which (per SYSTEM.md) is the rpc.dig.net read service. (The native node
   * resolves this directly from coinset.org; the companion delegates.)
   * @param {object} params { store_id }
   * @returns {Promise<object>} the JSON-RPC `result` object
   */
  async getAnchoredRoot(params) {
    return this._rpc("dig.getAnchoredRoot", params || {});
  }

  /**
   * Local verified retrieval for one resource. Returns
   * { bytes: Buffer, contentType, verified, source: "local"|"remote", urn }.
   *
   * @param {string} urn a chia:// / urn:dig: string (or bare storeId[:root][/res])
   */
  async getResource(urn) {
    const urnString = String(urn).replace(/^chia:\/\//, "");
    const parsed = parseURN(urnString);
    if (!parsed) throw new Error("invalid URN format");

    const sel = selectionFromParsed(parsed);
    const dig = await ensureDig();

    // retrievalKey = SHA256(canonical rootless URN), hex (wasm)
    const rk = dig.retrievalKey(sel.storeId, sel.resourceKey);
    const key = cacheKey(sel.storeId, sel.root, rk);
    const contentType = ctForPath(sel.resourceKey);
    const fullUrn = canonicalUrn(parsed);

    // 1. CACHE-FIRST: serve a previously resolved+decrypted resource (no network).
    const hit = await this.cache.get(key);
    if (hit) {
      return {
        bytes: hit.bytes,
        contentType: hit.meta.contentType || contentType,
        verified: !!hit.meta.verified,
        source: "local",
        urn: fullUrn,
      };
    }

    // 2. MISS: blind-fetch ciphertext + proof, then LOCAL verify + decrypt.
    const { ciphertext, proof, chunkLens } = await this._fetchCiphertext(
      sel.storeId,
      rk,
      sel.root
    );

    let verified = false;
    try {
      verified = !!dig.verifyInclusion(ciphertext, proof, sel.root);
    } catch {
      verified = false;
    }

    const keyHex = dig.deriveKey(sel.storeId, sel.resourceKey, sel.salt);
    let bytes;
    try {
      bytes = decryptChunks(dig, keyHex, ciphertext, chunkLens);
    } catch {
      throw new Error("decrypt failed (decoy or wrong key)");
    }
    const outBuf = Buffer.from(bytes);

    // 3. Cache the decrypted bytes locally for repeat serves.
    await this.cache
      .put(key, outBuf, { storeId: sel.storeId, root: sel.root, retrievalKey: rk, contentType, verified })
      .catch(() => {}); // cache write is best-effort; never fail the read

    return { bytes: outBuf, contentType, verified, source: "remote", urn: fullUrn };
  }

  /**
   * Blind passthrough for a raw JSON-RPC request body the companion does not
   * resolve locally (fallback). Returns the upstream's parsed JSON envelope.
   * @param {object} reqObj a JSON-RPC 2.0 request object
   */
  async proxyRaw(reqObj) {
    let res;
    try {
      res = await fetch(this.upstream, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(reqObj),
      });
    } catch (e) {
      throw new Error(`upstream unreachable: ${e?.message || e}`);
    }
    return res.json();
  }
}
