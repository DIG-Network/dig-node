/**
 * DIG Network URN Utilities
 * Centralized module for URN parsing, encoding, and URL conversion
 */

// Base36 encoding/decoding for store IDs (64 hex chars -> max 50 base36 chars)
function hexToInt(hex) {
  try {
    return BigInt('0x' + hex);
  } catch (e) {
    throw new Error(`Invalid hex string: ${hex}`);
  }
}

function intToBase36(bigInt) {
  if (bigInt === 0n) return '0';
  let result = '';
  const base = 36n;
  while (bigInt > 0n) {
    const remainder = Number(bigInt % base);
    const char = remainder < 10 
      ? remainder.toString()
      : String.fromCharCode(97 + remainder - 10); // 'a' = 97
    result = char + result;
    bigInt = bigInt / base;
  }
  return result;
}

function base36ToInt(base36) {
  let result = 0n;
  const base = 36n;
  for (let i = 0; i < base36.length; i++) {
    const char = base36[i].toLowerCase();
    let digit;
    if (char >= '0' && char <= '9') {
      digit = BigInt(parseInt(char, 10));
    } else if (char >= 'a' && char <= 'z') {
      digit = BigInt(char.charCodeAt(0) - 97 + 10);
    } else {
      throw new Error(`Invalid base36 character: ${char}`);
    }
    result = result * base + digit;
  }
  return result;
}

function intToHex(bigInt, length = 64) {
  let hex = bigInt.toString(16);
  return hex.padStart(length, '0');
}

/**
 * Encode store ID (64 hex chars) to base36 (max 50 chars)
 * @param {string} storeId - 64-character hexadecimal store ID
 * @returns {string} Base36 encoded store ID
 */
function encodeStoreId(storeId) {
  if (!/^[a-f0-9]{64}$/i.test(storeId)) {
    throw new Error('Invalid store ID format');
  }
  const int = hexToInt(storeId);
  return intToBase36(int);
}

/**
 * Decode base36 to store ID (64 hex chars)
 * @param {string} encoded - Base36 encoded store ID
 * @returns {string} 64-character hexadecimal store ID
 */
function decodeStoreId(encoded) {
  const int = base36ToInt(encoded);
  return intToHex(int, 64);
}

/**
 * Parse URN: urn:dig:{chain}:{storeId}:{roothash}/{resourceKey}[?salt=<hex>]
 *
 * Single shared parser for every consumer in the extension — the Node test server
 * (server.js, CommonJS require) and the module service worker (background.js, ESM
 * import). It accepts the union of inputs those callers pass: a `chia://` scheme
 * prefix, leading slashes, the `urn:dig:` prefix, and an optional `?salt=<hex>`
 * private-store query param. `salt` is always present in the result (null = public
 * store) so background.js's `parsed.salt ?? null` read is satisfied.
 *
 * parseURN returns `{ chain, storeId, roothash, resourceKey, salt }`. Capsule
 * semantics (canonical, see ../../SYSTEM.md): a capsule = one immutable store
 * generation = the pair `(storeId, rootHash)`, written `storeId:rootHash`; a
 * store is a sequence of capsules (one per commit). If `roothash` is present, the
 * URN identifies a SPECIFIC capsule (`storeId:roothash`). A rootless URN
 * (`roothash === null`) references the store's LATEST capsule.
 *
 * @param {string} urnString - URN string (with or without `chia://` / `urn:dig:` prefix)
 * @returns {Object|null} `{ chain, storeId, roothash, resourceKey, salt }` or null if invalid
 */
function parseURN(urnString) {
  if (!urnString || typeof urnString !== 'string') {
    return null;
  }

  // Remove chia:// scheme prefix if present (callers may pass the raw chia:// URL)
  urnString = urnString.replace(/^chia:\/\//i, '');

  // Remove leading slash(es) if present (path-style callers)
  urnString = urnString.replace(/^\/+/, '');

  // Remove urn:dig: prefix if present
  urnString = urnString.replace(/^urn:dig:/i, '');

  // Extract optional ?salt=<hex> query parameter before parsing the path
  let salt = null;
  const saltMatch = urnString.match(/[?&]salt=([0-9a-f]+)/i);
  if (saltMatch) {
    salt = saltMatch[1].toLowerCase();
  }
  // Strip salt param (handles ?salt=… or &salt=…) then strip any remaining query string
  urnString = urnString.replace(/[?&]salt=[0-9a-f]+/i, '').replace(/\?.*$/, '');

  // Parse components
  // Format: {chain}:{storeId}:{roothash}/{resourceKey}
  // or: {chain}:{storeId}/{resourceKey} (no roothash)
  const match = urnString.match(/^([^:]+):([a-f0-9]{64})(?::([a-f0-9]{64}))?(?:\/(.+))?$/i);

  if (!match) {
    // Try without chain prefix (assume chia)
    const simpleMatch = urnString.match(/^([a-f0-9]{64})(?::([a-f0-9]{64}))?(?:\/(.+))?$/i);
    if (simpleMatch) {
      return {
        chain: 'chia',
        storeId: simpleMatch[1].toLowerCase(),
        roothash: simpleMatch[2] ? simpleMatch[2].toLowerCase() : null,
        resourceKey: simpleMatch[3] || '',
        salt,
      };
    }
    return null;
  }

  return {
    chain: match[1].toLowerCase(),
    storeId: match[2].toLowerCase(),
    roothash: match[3] ? match[3].toLowerCase() : null,
    resourceKey: match[4] || '',
    salt,
  };
}

/**
 * Resolve hostname to URN (supports dig.local, localhost, and 127.0.0.1)
 * @param {string} hostname - Hostname from request
 * @param {string} pathname - Path from request
 * @returns {string|null} URN string or null if invalid
 */
function resolveHostToURN(hostname, pathname) {
  // Support both dig.local and localhost as base domains
  const baseDomains = ['dig.local', 'localhost', '127.0.0.1'];
  let baseDomain = null;
  let subdomainPart = null;
  
  // Check which base domain matches
  for (const domain of baseDomains) {
    if (hostname === domain) {
      baseDomain = domain;
      subdomainPart = '';
      break;
    } else if (hostname.endsWith('.' + domain)) {
      baseDomain = domain;
      subdomainPart = hostname.replace(new RegExp('\\.' + domain.replace(/\./g, '\\.') + '$'), '');
      break;
    }
  }
  
  if (!baseDomain) {
    return null;
  }
  
  // Handle direct base domain (no subdomain)
  if (hostname === baseDomain) {
    // Check if path is direct URN format
    if (pathname.startsWith('/urn:dig:')) {
      return pathname.substring(1); // Remove leading slash
    }
    // Check if path is path-based format (64-char hex store ID)
    const pathMatch = pathname.match(/^\/([a-f0-9]{64})(?:\/(.+))?$/i);
    if (pathMatch) {
      const storeId = pathMatch[1].toLowerCase();
      const resourceKey = pathMatch[2] || '';
      return `urn:dig:chia:${storeId}${resourceKey ? '/' + resourceKey : ''}`;
    }
    return null;
  }
  
  // Handle subdomain format
  const subdomains = subdomainPart.split('.');
  
  if (subdomains.length === 1) {
    // Latest version: {encodedStoreId}.{baseDomain}/{resourceKey}
    try {
      const encodedStoreId = subdomains[0];
      const storeId = decodeStoreId(encodedStoreId);
      const resourceKey = pathname === '/' ? '' : pathname.substring(1); // Remove leading slash
      return `urn:dig:chia:${storeId}${resourceKey ? '/' + resourceKey : ''}`;
    } catch (e) {
      console.error('Failed to decode store ID:', e);
      return null;
    }
  } else if (subdomains.length === 2) {
    // Specific version: {encodedStoreId}.{encodedRootHash}.{baseDomain}/{resourceKey}
    try {
      const encodedStoreId = subdomains[0];
      const encodedRootHash = subdomains[1];
      const storeId = decodeStoreId(encodedStoreId);
      const rootHash = decodeStoreId(encodedRootHash);
      const resourceKey = pathname === '/' ? '' : pathname.substring(1); // Remove leading slash
      return `urn:dig:chia:${storeId}:${rootHash}${resourceKey ? '/' + resourceKey : ''}`;
    } catch (e) {
      console.error('Failed to decode store ID or root hash:', e);
      return null;
    }
  }
  
  return null;
}

/**
 * Convert URN to content server URL
 * @param {string} urn - URN string
 * @param {Object} options - Options for URL generation
 * @param {string} options.host - Hostname (default: 'dig.local' or 'localhost' based on resolvability)
 * @param {number} options.port - Port number (default: 80)
 * @returns {string|null} Content server URL or null if invalid URN
 */
function urnToContentServerUrl(urn, options = {}) {
  const parsed = parseURN(urn);
  if (!parsed) {
    return null;
  }
  
  const host = options.host || 'dig.local';
  const port = options.port !== undefined ? options.port : 80;
  
  // Encode store ID to base36 for subdomain
  const encodedStoreId = encodeStoreId(parsed.storeId);
  
  // Build URL based on whether roothash is present
  let url;
  if (parsed.roothash) {
    // Specific version: http://{encodedStoreId}.{encodedRootHash}.{host}:{port}/{resourceKey}
    const encodedRootHash = encodeStoreId(parsed.roothash);
    const resourceKey = parsed.resourceKey || '';
    url = `http://${encodedStoreId}.${encodedRootHash}.${host}${port !== 80 ? ':' + port : ''}/${resourceKey}`;
  } else {
    // Latest version: http://{encodedStoreId}.{host}:{port}/{resourceKey}
    const resourceKey = parsed.resourceKey || '';
    url = `http://${encodedStoreId}.${host}${port !== 80 ? ':' + port : ''}/${resourceKey}`;
  }
  
  return url;
}

// Single source of truth. This file is an ES module: the shipping module service
// worker (background.js, manifest `"type": "module"`) imports these named exports
// directly. Node-side dev consumers (server/server.js, tests/) load it via dynamic
// `import()` since they run as CommonJS. There is no longer a second inlined copy
// of parseURN / the base36 helpers anywhere in the extension.
export {
  parseURN,
  resolveHostToURN,
  encodeStoreId,
  decodeStoreId,
  urnToContentServerUrl,
  hexToInt,
  intToBase36,
  base36ToInt,
  intToHex,
};

