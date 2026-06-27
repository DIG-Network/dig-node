// cache.js — on-disk local content cache for the companion's dig-node.
//
// Mirrors the native dig-node's local cache (digstore crates/dig-node + the
// cache.* RPC surface): resolved resources are cached on disk keyed by
// storeId:root:retrievalKey, served from cache on repeat, with an LRU size cap.
//
// Unlike the native node (which caches whole compiled .dig MODULES keyed by
// capsule storeId:rootHash), the companion caches per-RESOURCE decrypted blobs
// keyed by storeId:root:retrievalKey — the granularity the extension read path
// produces. The cache.* config semantics (cap_bytes floored at 64 MiB,
// getConfig/setCapBytes/clear) match the native node's contract so clients see
// the same surface.

import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// Floor the cap at 64 MiB so a stray 0 can't disable caching (mirrors the
// native dig-node / dig-wallet floor in crates/dig-node/src/lib.rs).
export const CACHE_CAP_FLOOR = 64 * 1024 * 1024;
const DEFAULT_CAP = 512 * 1024 * 1024; // 512 MiB default, like a generous local cache

/**
 * Derive the on-disk cache key for a resolved resource. PURE — no I/O — so it is
 * unit-testable and is the single source of truth for cache identity.
 *
 * Identity is (storeId, root, retrievalKey): the capsule generation plus the
 * per-resource retrieval key. A rootless ("latest") URN and a pinned-root URN
 * for the same resource are DIFFERENT cache entries, because "latest" can move.
 *
 * @param {string} storeId 64-hex store id
 * @param {string} root 64-hex root, or the sentinel "latest"
 * @param {string} retrievalKey 64-hex retrieval key (SHA256 of the URN)
 * @returns {string} a filesystem-safe key (sha256 of the canonical tuple, hex)
 */
export function cacheKey(storeId, root, retrievalKey) {
  const canonical = `${String(storeId).toLowerCase()}:${String(root).toLowerCase()}:${String(
    retrievalKey
  ).toLowerCase()}`;
  return createHash("sha256").update(canonical).digest("hex");
}

/** Default cache directory: $DIG_COMPANION_CACHE_DIR or <tmp>/dig-companion-cache. */
export function defaultCacheDir() {
  return (
    process.env.DIG_COMPANION_CACHE_DIR ||
    path.join(os.tmpdir(), "dig-companion-cache")
  );
}

/**
 * A simple LRU disk cache. Each entry is two files under the cache dir:
 *   <key>.bin  — the decrypted resource bytes
 *   <key>.json — metadata { storeId, root, retrievalKey, contentType, verified, size }
 * LRU recency is the .bin file mtime (bumped on every hit), matching the native
 * node's mtime-as-recency convention.
 */
export class DiskCache {
  /**
   * @param {{ dir?: string, capBytes?: number }} [opts]
   */
  constructor(opts = {}) {
    this.dir = opts.dir || defaultCacheDir();
    this._capBytes = Math.max(
      CACHE_CAP_FLOOR,
      Number(opts.capBytes) || DEFAULT_CAP
    );
    fs.mkdirSync(this.dir, { recursive: true });
  }

  _binPath(key) {
    return path.join(this.dir, `${key}.bin`);
  }
  _metaPath(key) {
    return path.join(this.dir, `${key}.json`);
  }

  get capBytes() {
    return this._capBytes;
  }

  /** Set the cap (floored at 64 MiB), then evict if now over. */
  async setCapBytes(bytes) {
    this._capBytes = Math.max(CACHE_CAP_FLOOR, Number(bytes) || 0);
    await this._evictIfNeeded();
    return this._capBytes;
  }

  /** Total bytes currently used by .bin entries. */
  usedBytes() {
    let total = 0;
    let files;
    try {
      files = fs.readdirSync(this.dir);
    } catch {
      return 0;
    }
    for (const f of files) {
      if (!f.endsWith(".bin")) continue;
      try {
        total += fs.statSync(path.join(this.dir, f)).size;
      } catch {
        /* race: file removed between readdir and stat */
      }
    }
    return total;
  }

  /**
   * Look up a cached resource. On hit, bumps recency (mtime) and returns
   * { bytes, meta }. On miss returns null.
   * @param {string} key
   * @returns {Promise<{bytes: Buffer, meta: object}|null>}
   */
  async get(key) {
    const binPath = this._binPath(key);
    const metaPath = this._metaPath(key);
    try {
      const [bytes, metaRaw] = await Promise.all([
        fsp.readFile(binPath),
        fsp.readFile(metaPath, "utf8"),
      ]);
      // Bump recency for LRU (best-effort).
      const now = new Date();
      fsp.utimes(binPath, now, now).catch(() => {});
      return { bytes, meta: JSON.parse(metaRaw) };
    } catch {
      return null;
    }
  }

  /**
   * Store a resolved resource. Writes bytes + metadata, then evicts LRU entries
   * if over the cap.
   * @param {string} key
   * @param {Buffer|Uint8Array} bytes
   * @param {object} meta
   */
  async put(key, bytes, meta) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    // Don't cache a single object bigger than the whole cap — pointless churn.
    if (buf.length > this._capBytes) return;
    const full = { ...meta, size: buf.length, cachedAtMs: Date.now() };
    await fsp.writeFile(this._binPath(key), buf);
    await fsp.writeFile(this._metaPath(key), JSON.stringify(full));
    await this._evictIfNeeded();
  }

  /** Remove all cache entries. */
  async clear() {
    let files;
    try {
      files = await fsp.readdir(this.dir);
    } catch {
      return;
    }
    await Promise.all(
      files
        .filter((f) => f.endsWith(".bin") || f.endsWith(".json"))
        .map((f) => fsp.rm(path.join(this.dir, f), { force: true }))
    );
  }

  /**
   * Evict least-recently-used entries until usedBytes <= capBytes.
   * LRU order = ascending .bin mtime.
   */
  async _evictIfNeeded() {
    let used = this.usedBytes();
    if (used <= this._capBytes) return;
    let entries;
    try {
      entries = (await fsp.readdir(this.dir)).filter((f) => f.endsWith(".bin"));
    } catch {
      return;
    }
    const stated = [];
    for (const f of entries) {
      try {
        const st = await fsp.stat(path.join(this.dir, f));
        stated.push({ f, mtime: st.mtimeMs, size: st.size });
      } catch {
        /* removed concurrently */
      }
    }
    stated.sort((a, b) => a.mtime - b.mtime); // oldest first
    for (const e of stated) {
      if (used <= this._capBytes) break;
      const key = e.f.slice(0, -4); // strip ".bin"
      await fsp.rm(this._binPath(key), { force: true }).catch(() => {});
      await fsp.rm(this._metaPath(key), { force: true }).catch(() => {});
      used -= e.size;
    }
  }
}
