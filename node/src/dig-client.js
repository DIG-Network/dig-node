// dig-client.js — Node loader for the vendored DIG read-crypto WASM.
//
// This is the companion's in-process port of the extension's `ensureDig()`
// (dig-chrome-extension/background.js). It loads the SAME `dig_client` WASM the
// extension uses, SRI-verifies it (fail closed), and returns the read-crypto
// functions: retrievalKey, deriveKey, verifyInclusion, decryptChunk.
//
// A LOCAL companion legitimately runs verify+decrypt: it is the user's own
// machine, exactly like the native DIG Browser's in-process dig-node. The
// "blind host" property only constrains REMOTE hosts (rpc.dig.net / cdn.dig.net),
// which still only ever see ciphertext + proofs.

import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(__dirname, "vendor", "dig_client_bg.wasm");
const GLUE_URL = new URL("./vendor/dig_client.mjs", import.meta.url);

// Same digest the extension (background.js) and hub (sw.js / dig-client.js) assert.
// See src/vendor/PROVENANCE.md. Fail closed on mismatch.
export const DIG_CLIENT_WASM_SHA256 =
  "ff486be806f908a2a90780e499a04dbd34e10e3b97be0470cb9ee841a1e49e77";

// Memoised init — load + verify + instantiate exactly once per process.
let _ready = null;

/**
 * Ensure the dig-client WASM is loaded and SRI-verified, then return the named
 * read-crypto functions. Safe to call concurrently; init runs at most once.
 * @returns {Promise<{retrievalKey: Function, deriveKey: Function, verifyInclusion: Function, decryptChunk: Function}>}
 */
export async function ensureDig() {
  if (!_ready) {
    _ready = (async () => {
      const bytes = await readFile(WASM_PATH);
      const hex = createHash("sha256").update(bytes).digest("hex");
      if (hex !== DIG_CLIENT_WASM_SHA256) {
        throw new Error(
          "dig-client wasm integrity check failed — refusing to run unverified crypto " +
            `(expected ${DIG_CLIENT_WASM_SHA256}, got ${hex})`
        );
      }
      const mod = await import(GLUE_URL.href);
      // wasm-bindgen default export = async init; accepts raw bytes via { module_or_path }.
      await mod.default({ module_or_path: bytes });
      return {
        retrievalKey: mod.retrievalKey,
        deriveKey: mod.deriveKey,
        verifyInclusion: mod.verifyInclusion,
        decryptChunk: mod.decryptChunk,
      };
    })();
  }
  return _ready;
}
