// DIG Browser native wallet — WalletConnect REQUESTER (delegate-to-Sage) role.
//
// The dual of the responder (entry.js): when the user picks "Sage" as the wallet
// source (#34), the embedded wallet becomes a WC CLIENT that pairs with the user's
// Sage wallet and forwards the FULL wallet surface — getPublicKeys, getAddress,
// getAssetBalance/getAssetCoins, signMessage/signMessageByAddress, signCoinSpends,
// takeOffer/createOffer, NFT/DID/etc. — over the session to Sage, returning Sage's
// responses (shapes normalized the way the hub's sage.js does).
//
// `window.chia` is UNCHANGED: it still talks to the loopback wallet, which routes to
// Sage via the delegate bridge (Rust `wc_dispatch` → /api/wc/delegate/* → here) when
// delegate mode is on. This module is the relay client the in-page delegate pump
// drives; the per-origin consent + broadcast gates are applied in Rust before any
// request ever reaches this layer.
//
// v1 persistence: the session lives in this page (the one tab that stays open), same
// caveat the responder documents. WalletConnect persists the session in this origin's
// IndexedDB, so a session paired from DIG settings is restorable here in the wallet.

import SignClient from "@walletconnect/sign-client";

// chia:mainnet + the CHIP-0002/chia method set we ask Sage to grant. We request the
// full surface as OPTIONAL namespaces (Sage rejects requiredNamespaces), mirroring the
// hub's walletconnect.js, so the session grants whatever Sage supports.
const CHIA_CHAIN = "chia:mainnet";
const REQUEST_METHODS = [
  "chip0002_connect",
  "chip0002_chainId",
  "chip0002_getPublicKeys",
  "chip0002_getAssetCoins",
  "chip0002_getAssetBalance",
  "chip0002_signCoinSpends",
  "chip0002_signMessage",
  "chia_getAddress",
  "chia_signMessageByAddress",
  "chia_takeOffer",
  "chia_createOffer",
  "chia_getOfferSummary",
  "chia_cancelOffer",
  "chia_send",
  "chia_getNfts",
  "chia_transferNft",
  "chia_mintNft",
  "chia_bulkMintNfts",
  "chia_getDids",
  "chia_createDidWallet",
  "chia_transferDid",
  "chia_getTransactions",
];

const REQUESTER_METADATA = {
  name: "DIG Browser",
  description: "DIG Browser wallet — delegating to Sage",
  url: "https://dig.net",
  icons: ["https://dig.net/favicon.ico"],
};

let client = null; // the requester SignClient (one per page)
let sessionsCb = null; // () => void — UI re-renders the Sage-connection state

/**
 * Initialise the requester with the effective projectId (from DIG settings).
 * Idempotent. Throws if no projectId is configured (the UI shows "not configured").
 * Reuses the same @walletconnect/sign-client the responder uses; the two roles share
 * the page's WC Core but keep independent sessions (responder sessions are dapps that
 * paired WITH us; the requester session is US paired with Sage).
 */
export async function initRequester(projectId, opts = {}) {
  if (!projectId) throw new Error("WalletConnect projectId not configured");
  if (client) return client;
  client = await SignClient.init({
    projectId,
    relayUrl: opts.relayUrl || "wss://relay.walletconnect.com",
    metadata: REQUESTER_METADATA,
  });
  client.on("session_delete", () => {
    if (sessionsCb) sessionsCb();
  });
  client.on("session_expire", () => {
    if (sessionsCb) sessionsCb();
  });
  return client;
}

/** Register the UI callback that re-renders the Sage-connection state. */
export function onSageSessionChanged(cb) {
  sessionsCb = cb;
}

/**
 * Begin pairing with Sage: returns `{ uri, approval }`. The UI shows `uri` as a
 * `wc:` link + QR for the user to paste/scan into Sage; `await approval()` resolves
 * to the established session once Sage approves. Like the hub, request the methods as
 * OPTIONAL namespaces (Sage rejects requiredNamespaces).
 */
export async function connectSage() {
  if (!client) throw new Error("WalletConnect not initialised");
  const { uri, approval } = await client.connect({
    optionalNamespaces: {
      chia: { methods: REQUEST_METHODS, chains: [CHIA_CHAIN], events: [] },
    },
  });
  return { uri, approval };
}

/** The active Sage session (the most recent), or null if not connected. */
export function sageSession() {
  if (!client) return null;
  const all = client.session.getAll();
  return all.length ? all[all.length - 1] : null;
}

/** Sage peer metadata for the connected-state UI (name/url/icon), or null. */
export function sagePeer() {
  const s = sageSession();
  return s && s.peer && s.peer.metadata ? s.peer.metadata : null;
}

/** Disconnect (and forget) the Sage session. */
export async function disconnectSage() {
  if (!client) return;
  const all = client.session.getAll();
  await Promise.all(
    all.map((s) =>
      client
        .disconnect({ topic: s.topic, reason: { code: 6000, message: "User disconnected" } })
        .catch(() => {})
    )
  );
  if (sessionsCb) sessionsCb();
}

// The methods the active Sage session granted. A session paired before a method was
// in our list will not include it, and SignClient rejects request() LOCALLY; we
// pre-check so the delegate pump can surface an actionable error instead of a silent
// local rejection. Empty list = unknown → treat as granted.
function sessionMethods(topic) {
  try {
    return client?.session?.get(topic)?.namespaces?.chia?.methods ?? [];
  } catch {
    return [];
  }
}

/**
 * Forward ONE wallet method to Sage over the session and return the NORMALIZED bare
 * result (the same shapes the local signer / hub `sage.js` produce, so the rest of
 * the wallet UI and `window.chia` consumers don't care whether the answer came from
 * local keys or Sage). Throws if not connected, the method wasn't granted, or Sage
 * rejects — the delegate pump turns that into the bridge's error reply.
 */
export async function sageRequest(method, params) {
  const s = sageSession();
  if (!s) throw new Error("Sage wallet is not connected");
  const topic = s.topic;
  const granted = sessionMethods(topic);
  // Handshake methods are answered locally in Rust, so they never reach here; for any
  // other method, if the session didn't grant it, fail fast with a reconnect hint.
  if (granted.length && !granted.includes(method)) {
    throw new Error(
      `Your Sage session does not grant "${method}". Reconnect Sage to refresh the session.`
    );
  }
  const resp = await client.request({
    topic,
    chainId: CHIA_CHAIN,
    request: { method, params: params || {} },
  });
  return normalizeSageResult(method, resp);
}

// ---- Sage response normalization (ported from hub apps/web/lib/sage.js) ------
//
// Sage returns wallet-specific casing, with or without 0x; the local signer returns a
// canonical shape. Normalize per method so a delegated answer is byte-compatible with
// the native one for the wallet UI + the injected `window.chia` consumers.

function with0x(hex) {
  if (!hex) return hex;
  return hex.startsWith("0x") ? hex : `0x${hex}`;
}

function pickBalance(resp) {
  const raw =
    resp == null
      ? null
      : typeof resp === "object"
        ? (resp.confirmed ??
          resp.spendable ??
          resp.confirmedWalletBalance ??
          resp.confirmed_wallet_balance ??
          resp.balance ??
          resp.data?.confirmed ??
          null)
        : resp;
  if (raw == null) return null;
  try {
    return BigInt(raw).toString();
  } catch {
    return null;
  }
}

function normalizeSageResult(method, resp) {
  switch (method) {
    case "chia_getAddress": {
      const address =
        typeof resp === "string" ? resp : (resp?.address ?? resp?.data?.address ?? null);
      return { address };
    }
    case "chip0002_getPublicKeys": {
      const keys = Array.isArray(resp)
        ? resp
        : (resp?.publicKeys ?? resp?.public_keys ?? resp?.keys ?? []);
      return keys;
    }
    case "chip0002_signMessage":
    case "chia_signMessageByAddress": {
      const publicKey = resp?.publicKey ?? resp?.public_key ?? resp?.pubkey ?? null;
      const signature =
        typeof resp === "string"
          ? resp
          : (resp?.signature ??
            resp?.aggregatedSignature ??
            resp?.aggregated_signature ??
            null);
      return { publicKey: with0x(publicKey), signature };
    }
    case "chip0002_signCoinSpends": {
      const signature =
        typeof resp === "string"
          ? resp
          : (resp?.signature ??
            resp?.aggregatedSignature ??
            resp?.aggregated_signature ??
            "");
      return signature;
    }
    case "chip0002_getAssetBalance": {
      const confirmed = pickBalance(resp);
      // Local signer returns { confirmed, spendable }; mirror that shape.
      return { confirmed, spendable: confirmed };
    }
    case "chip0002_getAssetCoins": {
      const coins = Array.isArray(resp) ? resp : (resp?.coins ?? []);
      return { coins };
    }
    default:
      // Everything else (offers, NFTs, DIDs, transactions, send) is passed through —
      // the wallet UI and window.chia consumers tolerate Sage's native shape, same as
      // the hub does for these methods.
      return resp;
  }
}
