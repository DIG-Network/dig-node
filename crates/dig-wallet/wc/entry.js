// DIG Browser native wallet — WalletConnect RESPONDER (wallet) entry.
//
// Bundled (esbuild, IIFE) into the wallet UI page and exposed as `window.DigWC`.
// The native wallet plays the WALLET side of WalletConnect (the dual of Sage):
// it pairs from a dapp's `wc:` URI, surfaces the session proposal for the user to
// approve/reject in the wallet UI, and on each `session_request` routes the
// {method, params} to the EXISTING loopback signer at `POST /api/wc/request` —
// so ALL signing stays in the Rust `wc_dispatch` (one source of truth, same
// per-origin consent + the DIG_WALLET_ALLOW_BROADCAST gate). The mnemonic / key
// export is NEVER touched here: this page only forwards method calls.
//
// v1 persistence limit: the responder lives in this page, so sessions are alive
// only while dig://wallet is open. A persistent background responder is v2.

import SignClient from "@walletconnect/sign-client";
import { callLocalSigner, METHOD_NOT_FOUND } from "./signer.js";

// Re-export so the wallet page can call the bridge directly if needed.
export { callLocalSigner };

// The REQUESTER (delegate-to-Sage) role — the dual of this responder (#34). When the
// user picks "Sage" as the wallet source, the page uses these to pair with Sage and
// the in-page delegate pump uses `sageRequest` to forward each wallet method to Sage.
// `window.chia` is unchanged; only the signer moves to Sage.
export {
  initRequester,
  connectSage,
  sageSession,
  sagePeer,
  disconnectSage,
  onSageSessionChanged,
  sageRequest,
} from "./requester.js";

// QR helper for the connect-to-Sage pairing URI (scan into Sage on another device).
export { qrSvg } from "./qr.js";

// The chia/CHIP-0002 surface the native signer implements (mirrors Sage's WC
// namespace). These are advertised in the session namespace and accepted on
// session_request; anything else is rejected.
const CHIA_CHAIN = "chia:mainnet";
const CHIA_METHODS = [
  "chia_getAddress",
  "chia_signMessageByAddress",
  "chia_takeOffer",
  "chip0002_chainId",
  "chip0002_connect",
  "chip0002_getPublicKeys",
  "chip0002_signMessage",
  "chip0002_signCoinSpends",
  "chip0002_getAssetBalance",
  "chip0002_getAssetCoins",
];
const CHIA_EVENTS = ["chainChanged", "accountsChanged"];

const WALLET_METADATA = {
  name: "DIG Wallet",
  description: "DIG Browser built-in Chia wallet",
  url: "https://dig.net",
  icons: ["https://dig.net/favicon.ico"],
};

let client = null; // the SignClient instance (one per page)
let proposalCb = null; // (proposal) => void — UI surfaces it for approve/reject
let sessionsCb = null; // () => void — UI re-renders the active-session list

/**
 * Initialise the responder with the effective projectId (from DIG settings).
 * Idempotent: a second call with the same projectId is a no-op. Throws if no
 * projectId is configured (the UI shows the "not configured" state instead).
 */
export async function init(projectId, opts = {}) {
  if (!projectId) throw new Error("WalletConnect projectId not configured");
  if (client) return client;
  client = await SignClient.init({
    projectId,
    relayUrl: opts.relayUrl || "wss://relay.walletconnect.com",
    metadata: WALLET_METADATA,
  });

  // A dapp proposes a session after pairing — hand it to the UI to approve/reject.
  client.on("session_proposal", (event) => {
    if (proposalCb) proposalCb(event);
  });

  // Each signing request from a connected dapp → forward to the local signer.
  client.on("session_request", (event) => {
    handleSessionRequest(event).catch((e) =>
      console.error("[DigWC] session_request failed", e)
    );
  });

  client.on("session_delete", () => {
    if (sessionsCb) sessionsCb();
  });

  return client;
}

/** Register the UI callbacks (proposal surfacing + session-list refresh). */
export function onProposal(cb) {
  proposalCb = cb;
}
export function onSessionsChanged(cb) {
  sessionsCb = cb;
}

/** Pair with a dapp from its `wc:` URI (pasted/scanned in the wallet UI). */
export async function pair(uri) {
  if (!client) throw new Error("WalletConnect not initialised");
  await client.core.pairing.pair({ uri: uri.trim() });
}

/**
 * Approve a surfaced proposal for the wallet's `address`, establishing the
 * chia:mainnet session for the supported method set. Returns the session topic.
 */
export async function approve(proposal, address) {
  if (!client) throw new Error("WalletConnect not initialised");
  const { id, params } = proposal;
  // Honour whatever the dapp requested under the chia namespace, but always cap
  // the methods/events to what the native signer actually implements.
  const account = `${CHIA_CHAIN}:${address}`;
  const namespaces = {
    chia: {
      chains: [CHIA_CHAIN],
      methods: CHIA_METHODS,
      events: CHIA_EVENTS,
      accounts: [account],
    },
  };
  const { topic, acknowledged } = await client.approveSession({
    id,
    namespaces,
  });
  await acknowledged();
  if (sessionsCb) sessionsCb();
  return topic;
}

/** Reject a surfaced proposal (user declined). */
export async function reject(proposal) {
  if (!client) throw new Error("WalletConnect not initialised");
  await client.rejectSession({
    id: proposal.id,
    reason: { code: 5000, message: "User rejected" },
  });
}

/** Active sessions, shaped for the UI (topic + dapp metadata). */
export function sessions() {
  if (!client) return [];
  return client.session.getAll().map((s) => ({
    topic: s.topic,
    peer: s.peer && s.peer.metadata ? s.peer.metadata : {},
  }));
}

/** Disconnect (and forget) an active session by topic. */
export async function disconnect(topic) {
  if (!client) return;
  try {
    await client.disconnectSession({
      topic,
      reason: { code: 6000, message: "User disconnected" },
    });
  } catch (e) {
    /* already gone */
  }
  if (sessionsCb) sessionsCb();
}

/**
 * Route ONE session_request to the loopback signer and respond over the relay.
 * The dapp's request carries {method, params}; we POST it verbatim to
 * `/api/wc/request` (same body the injected provider uses), so the Rust
 * `wc_dispatch` applies the identical consent + broadcast gates. The signer's
 * `data` (the bare Sage-shaped result) is returned as the JSON-RPC result.
 */
async function handleSessionRequest(event) {
  const { topic, params, id } = event;
  const { request } = params;
  let response;
  try {
    const data = await callLocalSigner(request.method, request.params);
    response = { id, jsonrpc: "2.0", result: data };
  } catch (e) {
    response = {
      id,
      jsonrpc: "2.0",
      error: { code: e.code || METHOD_NOT_FOUND, message: String(e.message || e) },
    };
  }
  await client.respondSessionRequest({ topic, response });
}
