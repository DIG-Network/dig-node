//! The dig-node chat subsystem — the TRANSPORT half of dig-chat (epic #793, Lane B).
//!
//! dig-node is the courier, never the correspondent. An application (the DIG Browser chat UI, a CLI)
//! hands the node an already-sealed **opaque `DIGCHAT1` envelope** plus the recipient it is for; the
//! node wraps that opaque blob in a [`dig_message`] envelope sealed to the recipient's `0x0010` BLS
//! identity key and hands the sealed bytes to [`dig_gossip`] for a directed peer send. Inbound, the
//! node opens the [`dig_message`] envelope, routes it through the chat [`MessageRegistry`], and queues
//! the decoded [`ChatMessage`] into a per-node inbox that the `chat.poll` RPC drains.
//!
//! ## The double seal (NC-1 — content-blindness)
//! Two independent seals stack, so no intermediary ever sees plaintext:
//! 1. the **inner** `DIGCHAT1` seal the app applies to the message body (this layer never parses it —
//!    [`ChatMessage::envelope`] carries it verbatim);
//! 2. the **outer** [`dig_message`] e2e seal to the recipient's BLS identity key, which is what
//!    dig-gossip actually carries over opcode 220.
//! A relay or on-path peer sees only the outer ciphertext; even a peer that terminates the outer seal
//! would still face the inner `DIGCHAT1` seal. The node is content-blind by construction.
//!
//! ## What is deliberately NOT here (MVP scope, epic #793)
//! - **Sealing-key resolution (`resolveSealingKey`).** Mapping a recipient DID to its attested `0x0010`
//!   BLS sealing key + its gossip [`PeerId`] is the deferred key directory; for the MVP the calling app
//!   supplies both (see `chat.send` params). Inbound sender-key resolution is likewise a caller-supplied
//!   [`SenderKeyResolver`]; until the directory lands an unresolvable sender is dropped, never trusted.
//! - Group chat, onion routing, and receipt UX. The five types + directed send/receive only.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chia_protocol::Bytes32;
use dig_chat_protocol::{
    register_all, ChatHandler, ChatMessage, DeliveryReceipt, Presence, ReadReceipt,
    TypingIndicator, ID_CHAT_MESSAGE,
};
use dig_message::{
    decode_envelope, open_message, seal_message, InteractionShape, MessageRegistry, MessageType,
    ReplayGuard, SealParams,
};
use dig_tls::bls::{public_key_bytes, SecretKey};
use sha2::{Digest, Sha256};

/// The dig-message freshness window is 5 minutes; a sealed chat message expires one window after it is
/// sent so a captured envelope cannot be replayed indefinitely (dig-message §5.6b).
const CHAT_TTL_MS: u64 = 300_000;

/// Resolves a message sender's `(DID, key epoch)` to its 48-byte BLS G1 identity public key, so an
/// inbound envelope's signature + auth-decap can be verified. Returns `None` for an unknown sender
/// (the message is then dropped, never trusted). The production implementation is the deferred key
/// directory; the MVP passes a caller-supplied closure.
pub type SenderKeyResolver<'a> = dyn Fn(Bytes32, u32) -> Option<[u8; 48]> + 'a;

/// A decoded inbound chat message queued for the paired application to poll.
///
/// It carries only what the app needs to render + correlate: who sent it (the verified envelope
/// sender DID), the application message id, and the still-opaque `DIGCHAT1` body. The body is never
/// parsed by the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundChat {
    /// The verified sender DID launcher id from the opened [`dig_message`] envelope.
    pub sender_did: Bytes32,
    /// The application message id from the [`ChatMessage`].
    pub message_id: Bytes32,
    /// The opaque `DIGCHAT1` content seal, carried verbatim — never parsed by the node.
    pub envelope: Vec<u8>,
}

/// A bounded FIFO of decoded inbound chat messages awaiting a `chat.poll`.
///
/// The subsystem pushes as directed messages arrive; `chat.poll` drains. Bounded so a peer that spams
/// a node it is paired with cannot grow memory without limit — the oldest queued message is dropped
/// once [`ChatInbox::CAPACITY`] is reached (the paired app is expected to poll promptly).
#[derive(Debug, Default)]
pub struct ChatInbox {
    queue: Mutex<VecDeque<InboundChat>>,
}

impl ChatInbox {
    /// The most inbound messages held before the oldest is dropped to bound memory.
    pub const CAPACITY: usize = 4096;

    /// An empty inbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue one decoded inbound message, evicting the oldest if the inbox is at capacity.
    pub fn push(&self, message: InboundChat) {
        let mut queue = self.queue.lock().expect("chat inbox mutex poisoned");
        if queue.len() >= Self::CAPACITY {
            queue.pop_front();
        }
        queue.push_back(message);
    }

    /// Remove and return every queued message in arrival order, leaving the inbox empty.
    pub fn drain(&self) -> Vec<InboundChat> {
        let mut queue = self.queue.lock().expect("chat inbox mutex poisoned");
        queue.drain(..).collect()
    }

    /// The number of messages currently queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.lock().expect("chat inbox mutex poisoned").len()
    }

    /// Whether no messages are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The per-node chat state: the inbound message inbox plus the monotonic anti-replay send counter.
///
/// One value lives on the [`crate::Node`]; the send counter is strictly increasing across the process
/// so each sealed message a node emits carries a fresh counter (dig-message §5.6 anti-replay).
#[derive(Debug)]
pub struct ChatState {
    /// Decoded inbound messages awaiting `chat.poll`.
    pub inbox: Arc<ChatInbox>,
    /// The strictly-monotonic per-node anti-replay counter, seeded from wall-clock ms so it keeps
    /// increasing across restarts.
    send_counter: AtomicU64,
}

impl Default for ChatState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatState {
    /// Fresh chat state with an empty inbox and a time-seeded send counter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inbox: Arc::new(ChatInbox::new()),
            send_counter: AtomicU64::new(now_ms()),
        }
    }

    /// The next strictly-greater anti-replay counter for an outbound message.
    fn next_counter(&self) -> u64 {
        self.send_counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Current wall-clock time in Unix milliseconds (the dig-message freshness clock).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Derive a deterministic application message id for an outbound chat message.
///
/// `SHA-256(sender_did ‖ counter ‖ opaque_envelope)` — a content-derived id (never an integer literal
/// nonce, CodeQL) that is unique per (sender, counter) and stable for a given body.
fn derive_message_id(sender_did: Bytes32, counter: u64, envelope: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(sender_did.as_ref());
    hasher.update(counter.to_be_bytes());
    hasher.update(envelope);
    let digest: [u8; 32] = hasher.finalize().into();
    Bytes32::from(digest)
}

/// The DID a node seals as when it originates a chat message: `SHA-256(node BLS G1 public key)`.
///
/// The node's `0x0010` identity is a BLS keypair, not a DID-anchored singleton, so for the MVP the
/// sender DID is derived deterministically from that public key. A recipient's [`SenderKeyResolver`]
/// resolves this DID back to the same public key. (A real DID launcher id supersedes this once the key
/// directory lands — the deferred `resolveSealingKey` work.)
#[must_use]
pub fn node_sender_did(node_sk: &SecretKey) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes(node_sk));
    let digest: [u8; 32] = hasher.finalize().into();
    Bytes32::from(digest)
}

/// The sealed outbound bytes plus the id the node minted for the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChat {
    /// The application message id `chat.send` returns to the caller.
    pub message_id: Bytes32,
    /// The dig-message-sealed envelope bytes handed to dig-gossip's directed send.
    pub sealed: Vec<u8>,
}

/// Seal an app-supplied opaque `DIGCHAT1` envelope into a directed [`dig_message`] envelope addressed
/// to `recipient_pub` (the recipient's `0x0010` BLS identity key), sent as the node identity.
///
/// The returned [`SealedChat::sealed`] bytes are the opaque payload dig-gossip carries over opcode 220
/// — a peer sees only this outer ciphertext (NC-1). This function never inspects `opaque_envelope`.
///
/// # Errors
/// A stringified [`dig_message::MessageError`] if `recipient_pub` fails its subgroup check or the seal
/// fails.
pub fn seal_outbound(
    node_sk: &SecretKey,
    recipient_did: Bytes32,
    recipient_pub: &[u8; 48],
    opaque_envelope: &[u8],
    counter: u64,
) -> Result<SealedChat, String> {
    let sender_did = node_sender_did(node_sk);
    let message_id = derive_message_id(sender_did, counter, opaque_envelope);

    // The typed payload the recipient decodes: the app message id + the opaque DIGCHAT1 body. This
    // whole struct is compressed + sealed by dig-message below, so the message id + body are ciphertext
    // on the wire.
    let payload = encode_chat_message(&ChatMessage {
        message_id,
        envelope: opaque_envelope.to_vec(),
    })?;

    let now = now_ms();
    let envelope = seal_message(&SealParams {
        sender_sk: node_sk,
        sender: sender_did,
        sender_epoch: 0,
        recipient: recipient_did,
        recipient_pub,
        message_type: ID_CHAT_MESSAGE.0,
        shape: InteractionShape::OneShot,
        correlation_id: message_id,
        stream: None,
        counter,
        timestamp_ms: now,
        expires_at: now + CHAT_TTL_MS,
        payload: &payload,
    })
    .map_err(|e| format!("seal chat message: {e}"))?;

    let sealed = dig_message::encode_envelope(&envelope)
        .map_err(|e| format!("encode chat envelope: {e}"))?;
    Ok(SealedChat { message_id, sealed })
}

/// Open an inbound directed [`dig_message`] envelope, route it through the chat registry, and queue
/// any decoded [`ChatMessage`] into `inbox`.
///
/// `resolve_sender` maps the envelope's cleartext `(sender DID, epoch)` to the sender's BLS G1 key so
/// the signature + auth-decap verify; an unresolvable sender is rejected (never trusted). Receipts,
/// typing, and presence types are recognised + decoded (so an unknown in-band id still fails cleanly)
/// but are not surfaced to the poll inbox in the MVP.
///
/// # Errors
/// A stringified [`dig_message::MessageError`] if the envelope fails to decode, the sender is
/// unresolvable, or the seal/signature/replay/expiry checks fail. A well-formed envelope from an
/// untrusted sender is an error, not a queued message — fail closed.
pub fn open_into_inbox(
    recipient_sk: &SecretKey,
    sealed: &[u8],
    resolve_sender: &SenderKeyResolver<'_>,
    guard: &mut ReplayGuard,
    inbox: &Arc<ChatInbox>,
) -> Result<(), String> {
    let envelope = decode_envelope(sealed).map_err(|e| format!("decode chat envelope: {e}"))?;
    let opened = open_message(recipient_sk, &envelope, resolve_sender, guard, now_ms())
        .map_err(|e| format!("open chat envelope: {e}"))?;

    // Route the decoded payload through the chat type registry, capturing the verified sender so the
    // ChatMessage handler can stamp it onto the queued record.
    let mut registry = MessageRegistry::new();
    let handler = Arc::new(InboxHandler {
        inbox: Arc::clone(inbox),
        sender_did: opened.sender,
    });
    register_all(&mut registry, handler).map_err(|e| format!("register chat types: {e}"))?;
    registry
        .dispatch(
            MessageType(opened.message_type),
            opened.shape,
            &opened.payload,
        )
        .map_err(|e| format!("dispatch chat message: {e}"))?;
    Ok(())
}

/// Process one inbound directed frame the peer network delivered, queuing a decoded chat message.
///
/// The peer-network inbound loop calls this for every `(PeerId, Message)` it receives: a non-opcode-220
/// frame is ignored (returns `Ok(false)`); an opcode-220 frame is opened + dispatched into `inbox`
/// (returns `Ok(true)` on a queued message). `resolve_sender` is the sender-key directory
/// (`resolveSealingKey`, deferred — epic #793); until it can resolve a sender, its frames are rejected
/// rather than trusted.
///
/// # Errors
/// A stringified error if an opcode-220 frame fails to open/verify/dispatch (a malformed, untrusted,
/// replayed, or expired envelope) — the transport logs it and moves on; it is never a panic.
pub fn process_inbound_frame(
    recipient_sk: &SecretKey,
    msg_type: u8,
    data: &[u8],
    resolve_sender: &SenderKeyResolver<'_>,
    guard: &mut ReplayGuard,
    inbox: &Arc<ChatInbox>,
) -> Result<bool, String> {
    if !dig_gossip::is_dig_message(msg_type) {
        return Ok(false);
    }
    let before = inbox.len();
    open_into_inbox(recipient_sk, data, resolve_sender, guard, inbox)?;
    Ok(inbox.len() > before)
}

/// The [`ChatHandler`] that queues a decoded [`ChatMessage`] into the node inbox, stamping it with the
/// verified envelope sender. The non-message chat types are decoded (proving they are well-formed) but
/// dropped in the MVP — only messages surface to `chat.poll`.
struct InboxHandler {
    inbox: Arc<ChatInbox>,
    sender_did: Bytes32,
}

impl ChatHandler for InboxHandler {
    fn on_chat_message(&self, message: ChatMessage) -> dig_message::Result<()> {
        self.inbox.push(InboundChat {
            sender_did: self.sender_did,
            message_id: message.message_id,
            envelope: message.envelope,
        });
        Ok(())
    }

    fn on_delivery_receipt(&self, _receipt: DeliveryReceipt) -> dig_message::Result<()> {
        Ok(())
    }

    fn on_read_receipt(&self, _receipt: ReadReceipt) -> dig_message::Result<()> {
        Ok(())
    }

    fn on_typing_indicator(&self, _indicator: TypingIndicator) -> dig_message::Result<()> {
        Ok(())
    }

    fn on_presence(&self, _presence: Presence) -> dig_message::Result<()> {
        Ok(())
    }
}

/// Serialize a [`ChatMessage`] to its byte-deterministic Streamable payload.
fn encode_chat_message(message: &ChatMessage) -> Result<Vec<u8>, String> {
    use chia_traits::Streamable as _;
    message
        .to_bytes()
        .map_err(|e| format!("encode chat message payload: {e}"))
}

/// Mint the next outbound anti-replay counter for `state` — the seam the RPC layer uses so tests can
/// drive [`seal_outbound`] with an explicit counter while production stays monotonic.
#[must_use]
pub fn next_send_counter(state: &ChatState) -> u64 {
    state.next_counter()
}

// ── The RPC surface on the node (dispatched from `seams::dig_rpc`) ──────────────────────────────

use serde_json::{json, Value};

/// JSON-RPC error codes for the chat surface (in the node's private application range).
mod rpc_code {
    /// The node has no persistent identity key, so it cannot seal as a sender.
    pub const NO_IDENTITY: i64 = -32050;
    /// A required parameter was missing or malformed.
    pub const BAD_PARAMS: i64 = -32602;
    /// The peer network is not up (no gossip pool), so a directed send has no transport.
    pub const NO_PEER_NETWORK: i64 = -32051;
    /// The seal or the directed send failed.
    pub const SEND_FAILED: i64 = -32052;
}

/// Decode a required 64-hex (optionally `0x`-prefixed) 32-byte parameter.
fn param_bytes32(params: &Value, key: &str) -> Result<Bytes32, String> {
    let hex_str = params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("params.{key} (64-hex) is required"))?;
    let raw = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|_| format!("params.{key} must be hex"))?;
    Bytes32::try_from(raw).map_err(|_| format!("params.{key} must be 32 bytes (64-hex)"))
}

/// Decode a required base64 parameter into bytes.
fn param_b64(params: &Value, key: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let s = params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("params.{key} (base64) is required"))?;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| format!("params.{key} must be valid base64"))
}

impl crate::Node {
    /// Handle `chat.send` — seal an app-supplied opaque `DIGCHAT1` envelope to the recipient and send
    /// it to the recipient peer over dig-gossip's directed opcode-220 transport.
    ///
    /// Params: `{ recipient_did (64-hex), recipient_pub (base64, 48-byte BLS G1 sealing key),
    /// peer_id (64-hex gossip target), envelope (base64, opaque DIGCHAT1 bytes) }`. `recipient_pub` +
    /// `peer_id` are app-supplied for the MVP — the DID→key/peer directory (`resolveSealingKey`) is the
    /// deferred key directory (epic #793). Result: `{ message_id (64-hex) }`.
    pub async fn chat_send(&self, params: &Value, id: Value) -> Value {
        let Some(seed) = self.identity_seed else {
            return chat_err(
                &id,
                rpc_code::NO_IDENTITY,
                "node has no identity key to seal as",
            );
        };
        let recipient_did = match param_bytes32(params, "recipient_did") {
            Ok(v) => v,
            Err(e) => return chat_err(&id, rpc_code::BAD_PARAMS, &e),
        };
        let peer_id = match param_bytes32(params, "peer_id") {
            Ok(v) => v,
            Err(e) => return chat_err(&id, rpc_code::BAD_PARAMS, &e),
        };
        let recipient_pub: [u8; 48] = match param_b64(params, "recipient_pub") {
            Ok(v) => match v.try_into() {
                Ok(a) => a,
                Err(_) => {
                    return chat_err(&id, rpc_code::BAD_PARAMS, "recipient_pub must be 48 bytes")
                }
            },
            Err(e) => return chat_err(&id, rpc_code::BAD_PARAMS, &e),
        };
        let opaque = match param_b64(params, "envelope") {
            Ok(v) => v,
            Err(e) => return chat_err(&id, rpc_code::BAD_PARAMS, &e),
        };

        let node_sk = SecretKey::from_seed(&seed);
        let counter = self.chat.next_counter();
        let sealed = match seal_outbound(&node_sk, recipient_did, &recipient_pub, &opaque, counter)
        {
            Ok(s) => s,
            Err(e) => return chat_err(&id, rpc_code::SEND_FAILED, &e),
        };

        let Some(gossip) = self.gossip.get() else {
            return chat_err(
                &id,
                rpc_code::NO_PEER_NETWORK,
                "no peer network to send over",
            );
        };
        match gossip
            .send_dig_message(dig_gossip::PeerId::from(peer_id), &sealed.sealed, None)
            .await
        {
            Ok(()) => json!({"jsonrpc":"2.0","id":id,
                "result":{"message_id": hex::encode(sealed.message_id.as_ref())}}),
            Err(e) => chat_err(
                &id,
                rpc_code::SEND_FAILED,
                &format!("directed send failed: {e}"),
            ),
        }
    }

    /// Handle `chat.poll` — drain and return every inbound chat message the node has queued since the
    /// last poll (the MVP delivery surface, mirroring the node's other pull-style control reads).
    ///
    /// Result: `{ messages: [{ sender_did, message_id, envelope (base64 opaque DIGCHAT1) }] }`.
    pub fn chat_poll(&self, id: Value) -> Value {
        use base64::Engine as _;
        let messages: Vec<Value> = self
            .chat
            .inbox
            .drain()
            .into_iter()
            .map(|m| {
                json!({
                    "sender_did": hex::encode(m.sender_did.as_ref()),
                    "message_id": hex::encode(m.message_id.as_ref()),
                    "envelope": base64::engine::general_purpose::STANDARD.encode(&m.envelope),
                })
            })
            .collect();
        json!({"jsonrpc":"2.0","id":id,"result":{"messages": messages}})
    }

    /// The chat inbox handle, so the peer-network bring-up can feed inbound opcode-220 frames into it.
    #[must_use]
    pub fn chat_inbox(&self) -> Arc<ChatInbox> {
        Arc::clone(&self.chat.inbox)
    }
}

/// Build a chat JSON-RPC error response.
fn chat_err(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic BLS key from a hashed label — never a hard-coded literal (CodeQL).
    fn key(label: &str) -> SecretKey {
        let mut hasher = Sha256::new();
        hasher.update(b"dig-chat-test-key");
        hasher.update(label.as_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        SecretKey::from_seed(&seed)
    }

    /// A hashed-seed opaque DIGCHAT1 body of `n` bytes — stands in for the app's inner seal.
    fn opaque(tag: &str, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut counter = 0u64;
        while out.len() < n {
            let mut hasher = Sha256::new();
            hasher.update(tag.as_bytes());
            hasher.update(counter.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            counter += 1;
        }
        out.truncate(n);
        out
    }

    /// The seal→send→receive round-trip delivers the EXACT opaque envelope bytes to the inbox.
    #[test]
    fn send_receive_round_trip_preserves_opaque_envelope() {
        let sender = key("sender");
        let recipient = key("recipient");
        let recipient_pub = public_key_bytes(&recipient);
        let recipient_did = node_sender_did(&recipient);
        let body = opaque("hello", 512);

        let sealed = seal_outbound(&sender, recipient_did, &recipient_pub, &body, 1).expect("seal");

        let sender_pub = public_key_bytes(&sender);
        let resolver = move |_did: Bytes32, _epoch: u32| Some(sender_pub);
        let inbox = Arc::new(ChatInbox::new());
        let mut guard = ReplayGuard::new();
        open_into_inbox(&recipient, &sealed.sealed, &resolver, &mut guard, &inbox).expect("open");

        let received = inbox.drain();
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0].envelope, body,
            "opaque body must round-trip byte-identically"
        );
        assert_eq!(received[0].message_id, sealed.message_id);
        assert_eq!(received[0].sender_did, node_sender_did(&sender));
    }

    /// NC-1: neither the opaque DIGCHAT1 body nor the plaintext message id appears in the on-wire
    /// sealed bytes — a relay/peer sees only ciphertext (the double seal).
    #[test]
    fn on_wire_bytes_are_ciphertext_only() {
        let sender = key("sender");
        let recipient = key("recipient");
        let recipient_pub = public_key_bytes(&recipient);
        let recipient_did = node_sender_did(&recipient);
        // A distinctive body so a substring search is meaningful.
        let body = opaque("secret-marker", 256);

        let sealed = seal_outbound(&sender, recipient_did, &recipient_pub, &body, 7).expect("seal");

        assert!(
            !contains(&sealed.sealed, &body),
            "the opaque DIGCHAT1 body must NOT appear in the sealed on-wire bytes"
        );
        assert!(
            !contains(&sealed.sealed, sealed.message_id.as_ref()),
            "the plaintext message id must NOT appear in the sealed on-wire bytes"
        );
    }

    /// An envelope from a sender the recipient cannot resolve is rejected, never queued.
    #[test]
    fn unresolvable_sender_is_rejected() {
        let sender = key("sender");
        let recipient = key("recipient");
        let recipient_pub = public_key_bytes(&recipient);
        let recipient_did = node_sender_did(&recipient);
        let sealed = seal_outbound(&sender, recipient_did, &recipient_pub, &opaque("x", 64), 1)
            .expect("seal");

        let resolver = |_did: Bytes32, _epoch: u32| None;
        let inbox = Arc::new(ChatInbox::new());
        let mut guard = ReplayGuard::new();
        let result = open_into_inbox(&recipient, &sealed.sealed, &resolver, &mut guard, &inbox);
        assert!(result.is_err());
        assert!(inbox.is_empty());
    }

    /// Malformed sealed bytes fail cleanly (no panic).
    #[test]
    fn malformed_envelope_fails_cleanly() {
        let recipient = key("recipient");
        let resolver = |_did: Bytes32, _epoch: u32| Some([0u8; 48]);
        let inbox = Arc::new(ChatInbox::new());
        let mut guard = ReplayGuard::new();
        let result = open_into_inbox(
            &recipient,
            b"not an envelope",
            &resolver,
            &mut guard,
            &inbox,
        );
        assert!(result.is_err());
        assert!(inbox.is_empty());
    }

    /// The inbox evicts the oldest message once it is full, bounding memory.
    #[test]
    fn inbox_is_bounded() {
        let inbox = ChatInbox::new();
        for i in 0..(ChatInbox::CAPACITY + 10) {
            inbox.push(InboundChat {
                sender_did: Bytes32::from([1u8; 32]),
                message_id: Bytes32::from([(i % 256) as u8; 32]),
                envelope: vec![],
            });
        }
        assert_eq!(inbox.len(), ChatInbox::CAPACITY);
    }

    /// The per-node send counter is strictly monotonic.
    #[test]
    fn send_counter_is_monotonic() {
        let state = ChatState::new();
        let a = next_send_counter(&state);
        let b = next_send_counter(&state);
        let c = next_send_counter(&state);
        assert!(a < b && b < c);
    }

    /// Whether `haystack` contains `needle` as a contiguous byte substring.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }
}
