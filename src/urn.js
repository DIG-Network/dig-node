// urn.js — URN parsing for the companion, using the SAME shared parser the
// extension and hub use (vendored from dig-chrome-extension/dig-urn.mjs).
//
// Re-exports parseURN unchanged so the companion can resolve a chia:// / urn:dig:
// string into { chain, storeId, roothash, resourceKey, salt } identically to the
// extension's fetchContentViaRPC pipeline.

export { parseURN } from "./vendor/dig-urn.mjs";

/**
 * Reconstruct the canonical full URN string for logging / cache keys, mirroring
 * the extension's fetchContentViaRPC (background.js).
 * @param {{storeId: string, roothash: string|null, resourceKey: string}} parsed
 * @returns {string}
 */
export function canonicalUrn(parsed) {
  const root = parsed.roothash ? ":" + parsed.roothash : "";
  const res = parsed.resourceKey ? "/" + parsed.resourceKey : "";
  return `urn:dig:chia:${parsed.storeId}${root}${res}`;
}

/**
 * Normalise the capsule-selection inputs from a parsed URN, matching the
 * extension's defaults:
 *  - root: the pinned capsule root, or the sentinel "latest" for a rootless URN
 *  - resourceKey: defaults to "index.html"
 *  - salt: hex private-store salt, or null for a public store
 * @param {{storeId: string, roothash: string|null, resourceKey: string, salt: string|null}} parsed
 * @returns {{storeId: string, root: string, resourceKey: string, salt: string|null}}
 */
export function selectionFromParsed(parsed) {
  return {
    storeId: parsed.storeId,
    root: parsed.roothash || "latest",
    resourceKey: parsed.resourceKey || "index.html",
    salt: parsed.salt ?? null,
  };
}
