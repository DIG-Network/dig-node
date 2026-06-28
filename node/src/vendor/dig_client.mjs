/* @ts-self-types="./dig_client.d.ts" */

/**
 * Decrypt a SINGLE GCM-SIV chunk under an explicit 32-byte `key` (hex). Returns
 * the plaintext bytes. A failed tag check (tamper / wrong key) is an error.
 * Low-level escape hatch; most callers want `decryptResource`.
 * @param {string} key_hex
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array}
 */
export function decryptChunk(key_hex, ciphertext) {
    const ptr0 = passStringToWasm0(key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.decryptChunk(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Full read pipeline for a resource's served ciphertext (Digstore §9.3 + §11),
 * returning the decrypted plaintext bytes. Steps, in order (gate-then-decrypt):
 *
 * 1. **Integrity gate** — verify the served bytes' merkle inclusion against the
 *    chain-anchored `trusted_root_hex` (proof base64 from `X-Dig-Inclusion-Proof`).
 * 2. **Confidentiality** — derive the URN key, split the PLAIN-concatenated
 *    chunk ciphertexts by `chunk_lens` (the per-chunk CIPHERTEXT byte lengths in
 *    order; D5/C9 — NO length framing on the wire), and AES-256-GCM-SIV-open
 *    each, concatenating plaintext in order.
 *
 * `chunk_lens` may be empty for the common single-chunk resource (the whole blob
 * is one GCM-SIV ciphertext). They MUST sum to `ciphertext.len()`.
 * @param {string} store_id_hex
 * @param {string} resource_key
 * @param {Uint8Array} ciphertext
 * @param {string} proof_b64
 * @param {string} trusted_root_hex
 * @param {string | null} [salt_hex]
 * @param {Uint32Array | null} [chunk_lens]
 * @returns {Uint8Array}
 */
export function decryptResource(store_id_hex, resource_key, ciphertext, proof_b64, trusted_root_hex, salt_hex, chunk_lens) {
    const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(proof_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    var ptr5 = isLikeNone(salt_hex) ? 0 : passStringToWasm0(salt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len5 = WASM_VECTOR_LEN;
    var ptr6 = isLikeNone(chunk_lens) ? 0 : passArray32ToWasm0(chunk_lens, wasm.__wbindgen_malloc);
    var len6 = WASM_VECTOR_LEN;
    const ret = wasm.decryptResource(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v8 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v8;
}

/**
 * Convenience wrapper around [`decrypt_resource`] returning the plaintext as a
 * UTF-8 string (for HTML/text resources rendered into the sandbox iframe).
 * @param {string} store_id_hex
 * @param {string} resource_key
 * @param {Uint8Array} ciphertext
 * @param {string} proof_b64
 * @param {string} trusted_root_hex
 * @param {string | null} [salt_hex]
 * @param {Uint32Array | null} [chunk_lens]
 * @returns {string}
 */
export function decryptResourceToText(store_id_hex, resource_key, ciphertext, proof_b64, trusted_root_hex, salt_hex, chunk_lens) {
    let deferred9_0;
    let deferred9_1;
    try {
        const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(proof_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(salt_hex) ? 0 : passStringToWasm0(salt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        var ptr6 = isLikeNone(chunk_lens) ? 0 : passArray32ToWasm0(chunk_lens, wasm.__wbindgen_malloc);
        var len6 = WASM_VECTOR_LEN;
        const ret = wasm.decryptResourceToText(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
        var ptr8 = ret[0];
        var len8 = ret[1];
        if (ret[3]) {
            ptr8 = 0; len8 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred9_0 = ptr8;
        deferred9_1 = len8;
        return getStringFromWasm0(ptr8, len8);
    } finally {
        wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
    }
}

/**
 * Derive the 32-byte AES-256 content key for a resource (Digstore §11.1/§11.4),
 * returned as lowercase hex. `salt_hex` is the 32-byte private-store secret salt
 * (omit / pass `null` for public stores). Mixing in a wrong/missing salt yields
 * a wrong key whose GCM-SIV tag will not verify.
 * @param {string} store_id_hex
 * @param {string} resource_key
 * @param {string | null} [salt_hex]
 * @returns {string}
 */
export function deriveKey(store_id_hex, resource_key, salt_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(salt_hex) ? 0 : passStringToWasm0(salt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.deriveKey(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Seal a resource's plaintext as ONE AES-256-GCM-SIV blob under its per-URN key — the inverse of
 * the read path's chunk decrypt. The browser uses this to PRE-ENCRYPT a file before upload so the
 * server compiles the `.dig` from ciphertext alone (it never sees plaintext or any key). The
 * output is the resource's whole-file ciphertext; `digstore compile --pre-encrypted` stores it
 * verbatim as the single chunk, and `decryptResource`/`decryptChunk` under the same URN reverses
 * it. `salt_hex` is the store's secret salt for a private store (omit for a public store).
 * @param {string} store_id_hex
 * @param {string} resource_key
 * @param {Uint8Array} plaintext
 * @param {string | null} [salt_hex]
 * @returns {Uint8Array}
 */
export function encryptResource(store_id_hex, resource_key, plaintext, salt_hex) {
    const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(salt_hex) ? 0 : passStringToWasm0(salt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.encryptResource(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * On module load, install a `globalThis.digClient` object exposing the read
 * API, so non-bundler consumers (the standalone usercontent loader) can call
 * `globalThis.digClient.verifyInclusion(...)` / `.decryptResourceToText(...)`
 * after the wasm initializes. ES-module consumers can instead import the named
 * functions directly. Idempotent and best-effort (no-op if `globalThis` lacks
 * `Object`, e.g. in a non-browser host).
 */
export function install_global() {
    wasm.install_global();
}

/**
 * Reconstruct the canonical ROOT-INDEPENDENT resource URN string for a store +
 * resource key: `urn:dig:chia:<store_id>[/<resource_key>]`. An empty resource
 * key resolves to the §8.5 default view `index.html`. This is the form whose
 * SHA-256 is the retrieval key and whose bytes seed the AES key.
 * @param {string} store_id_hex
 * @param {string} resource_key
 * @returns {string}
 */
export function reconstructUrn(store_id_hex, resource_key) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.reconstructUrn(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Reconstruct a ROOT-PINNED display URN: `urn:dig:chia:<store_id>:<root>/<key>`.
 * Useful for sharing a URN bound to a specific generation; the retrieval/AES
 * keys still use the rootless form (`reconstructUrn`).
 * @param {string} store_id_hex
 * @param {string} root_hex
 * @param {string} resource_key
 * @returns {string}
 */
export function reconstructUrnWithRoot(store_id_hex, root_hex, resource_key) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.reconstructUrnWithRoot(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * `retrieval_key = SHA-256(canonical_rootless_urn)`, lowercase hex (Digstore
 * §7.3; API §17). The CDN is addressed by this hash; the URN itself is never
 * sent. An empty resource key resolves to `index.html`.
 * @param {string} store_id_hex
 * @param {string} resource_key
 * @returns {string}
 */
export function retrievalKey(store_id_hex, resource_key) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(store_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(resource_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.retrievalKey(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verify that `ciphertext` is included under `trusted_root_hex` via the base64
 * merkle `proof_b64` (Digstore §9.3; API §18). Returns `true` on success and
 * `false` on ANY verification failure (tampered bytes, non-chaining path, or a
 * root mismatch / decoy) — a decoy or wrong-store response returns `false`
 * rather than throwing, so a caller can treat it as "not found in this store".
 * Throws only on malformed inputs (bad base64 / hex / proof encoding).
 * @param {Uint8Array} ciphertext
 * @param {string} proof_b64
 * @param {string} trusted_root_hex
 * @returns {boolean}
 */
export function verifyInclusion(ciphertext, proof_b64, trusted_root_hex) {
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(proof_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyInclusion(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Library version (matches the crate version), for SRI / compatibility checks.
 * @returns {string}
 */
export function version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_fdd633d4bb5dd76a: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_is_undefined_721f8decd50c87a3: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_ea4887a5f8f9a9db: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_new_2e117a478906f062: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_set_4564f7dc44fcb0c9: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_THIS_2fee5048bcca5938: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_ce44e66a4935da8c: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_44f6e0cb5e67cdad: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_168f178805d978fe: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [String, String, Option(String)], shim_idx: 1, ret: Result(String), inner_ret: Some(Result(String)) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h68a3f7e1b7047a46);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [String, String, Vector(U8), String, String, Option(String), Option(Vector(U32))], shim_idx: 5, ret: Result(Vector(U8)), inner_ret: Some(Result(Vector(U8))) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hc605e6b36f32dd24);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [String, String, Vector(U8), String, String, Option(String), Option(Vector(U32))], shim_idx: 6, ret: Result(String), inner_ret: Some(Result(String)) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h58cab831a65fd6c8);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [String, String], shim_idx: 2, ret: Result(String), inner_ret: Some(Result(String)) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hd4233470ad4ef59f);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Vector(U8), String, String], shim_idx: 3, ret: Result(Boolean), inner_ret: Some(Result(Boolean)) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h36771739d8dc18ae);
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 4, ret: String, inner_ret: Some(String) }, mutable: false }) -> Externref`.
            const ret = makeClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h61ffc6ac64470c43);
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./dig_client_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__h61ffc6ac64470c43(arg0, arg1) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.wasm_bindgen__convert__closures_____invoke__h61ffc6ac64470c43(arg0, arg1);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

function wasm_bindgen__convert__closures_____invoke__hd4233470ad4ef59f(arg0, arg1, arg2, arg3) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(arg2, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(arg3, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasm_bindgen__convert__closures_____invoke__hd4233470ad4ef59f(arg0, arg1, ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

function wasm_bindgen__convert__closures_____invoke__h36771739d8dc18ae(arg0, arg1, arg2, arg3, arg4) {
    const ptr0 = passArray8ToWasm0(arg2, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(arg3, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(arg4, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h36771739d8dc18ae(arg0, arg1, ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

function wasm_bindgen__convert__closures_____invoke__h68a3f7e1b7047a46(arg0, arg1, arg2, arg3, arg4) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(arg2, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(arg3, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(arg4) ? 0 : passStringToWasm0(arg4, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasm_bindgen__convert__closures_____invoke__h68a3f7e1b7047a46(arg0, arg1, ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

function wasm_bindgen__convert__closures_____invoke__hc605e6b36f32dd24(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) {
    const ptr0 = passStringToWasm0(arg2, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(arg3, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(arg4, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(arg5, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(arg6, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    var ptr5 = isLikeNone(arg7) ? 0 : passStringToWasm0(arg7, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len5 = WASM_VECTOR_LEN;
    var ptr6 = isLikeNone(arg8) ? 0 : passArray32ToWasm0(arg8, wasm.__wbindgen_malloc);
    var len6 = WASM_VECTOR_LEN;
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__hc605e6b36f32dd24(arg0, arg1, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v8 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v8;
}

function wasm_bindgen__convert__closures_____invoke__h58cab831a65fd6c8(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) {
    let deferred9_0;
    let deferred9_1;
    try {
        const ptr0 = passStringToWasm0(arg2, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(arg3, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(arg4, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(arg5, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(arg6, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(arg7) ? 0 : passStringToWasm0(arg7, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        var ptr6 = isLikeNone(arg8) ? 0 : passArray32ToWasm0(arg8, wasm.__wbindgen_malloc);
        var len6 = WASM_VECTOR_LEN;
        const ret = wasm.wasm_bindgen__convert__closures_____invoke__h58cab831a65fd6c8(arg0, arg1, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
        var ptr8 = ret[0];
        var len8 = ret[1];
        if (ret[3]) {
            ptr8 = 0; len8 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred9_0 = ptr8;
        deferred9_1 = len8;
        return getStringFromWasm0(ptr8, len8);
    } finally {
        wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
    }
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint32ArrayMemory0 = null;
function getUint32ArrayMemory0() {
    if (cachedUint32ArrayMemory0 === null || cachedUint32ArrayMemory0.byteLength === 0) {
        cachedUint32ArrayMemory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachedUint32ArrayMemory0;
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        try {
            return f(state.a, state.b, ...args);
        } finally {
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray32ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 4, 4) >>> 0;
    getUint32ArrayMemory0().set(arg, ptr / 4);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedUint32ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('dig_client_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
