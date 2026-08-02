//! Known-Answer-Test (KAT) harness for dig-chat-protocol — the golden vectors that pin the byte-level
//! wire contract of the five chat payloads (SPEC §2, §3, §5) plus the registry behaviour (SPEC §4).
//!
//! Golden values are committed as SHA-256 digests of the deterministic on-wire bytes: a digest change
//! means the wire format drifted, which MUST be an intentional, reviewed SemVer event — never an
//! accident. ALL test material is DERIVED from a hashed seed (never a hard-coded literal — CodeQL).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use chia_protocol::Bytes32;
use chia_traits::Streamable;
use dig_message::{InteractionShape, MessageBand, MessageRegistry, MessageType, Result};
use sha2::{Digest, Sha256};

use dig_chat_protocol::{
    register_all, ChatHandler, ChatMessage, DeliveryReceipt, DeliveryStatus, Presence,
    PresenceState, ReadReceipt, TypingIndicator, TypingState, CHAT_MESSAGE_TYPES, ID_CHAT_MESSAGE,
    ID_DELIVERY_RECEIPT, ID_PRESENCE, ID_READ_RECEIPT, ID_TYPING_INDICATOR,
};

// ── Deterministic, seed-derived test material (never a hard-coded literal — CodeQL). ──

/// SHA-256(tag ‖ counter) chained to `n` bytes — reproducible across runs and machines.
fn seeded(tag: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u64;
    while out.len() < n {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(counter.to_le_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(n);
    out
}

fn b32(tag: &[u8]) -> Bytes32 {
    Bytes32::new(seeded(tag, 32).try_into().unwrap())
}

/// Lowercase-hex SHA-256 of the on-wire bytes — the committed golden form.
fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ── Golden byte-vectors (SPEC §3 wire determinism). encode→bytes and bytes→decode round-trip. ──

/// Assert that `value` encodes to exactly `len` bytes with SHA-256 `want`, and decodes back identically.
fn assert_golden<T>(value: &T, len: usize, want: &str)
where
    T: Streamable + PartialEq + std::fmt::Debug,
{
    let bytes = value.to_bytes().unwrap();
    assert_eq!(bytes.len(), len, "wire length drifted");
    assert_eq!(
        digest(&bytes),
        want,
        "wire bytes drifted (byte-determinism regression)"
    );
    let decoded = T::from_bytes(&bytes).unwrap();
    assert_eq!(
        &decoded, value,
        "decode did not round-trip byte-identically"
    );
}

fn golden_chat_message() -> ChatMessage {
    ChatMessage {
        message_id: b32(b"chat-mid"),
        envelope: seeded(b"digchat1-blob", 40),
    }
}
fn golden_delivery_receipt() -> DeliveryReceipt {
    DeliveryReceipt {
        message_id: b32(b"deliv-mid"),
        status: DeliveryStatus::Delivered.as_u8(),
    }
}
fn golden_read_receipt() -> ReadReceipt {
    ReadReceipt {
        message_id: b32(b"read-mid"),
    }
}
fn golden_typing() -> TypingIndicator {
    TypingIndicator {
        conversation_id: b32(b"typing-conv"),
        state: TypingState::Started.as_u8(),
    }
}
fn golden_presence() -> Presence {
    Presence {
        state: PresenceState::Away.as_u8(),
    }
}

#[test]
fn kat_chat_message() {
    assert_golden(
        &golden_chat_message(),
        76,
        "1242949e1b33fe2c73f546f132c894d3a6a118499cbc1e0d24c54dbec306a984",
    );
}

#[test]
fn kat_delivery_receipt() {
    assert_golden(
        &golden_delivery_receipt(),
        33,
        "e3a3d3eebc8e5eeb2fb539366ad4f9c45ec7dcfa8b7735ac38a37476fc24bcf1",
    );
}

#[test]
fn kat_read_receipt() {
    assert_golden(
        &golden_read_receipt(),
        32,
        "5e79288de830117c1a6fa9ce8efad1ccb8ad3a699a2b71c1c74cb3c66fd79958",
    );
}

#[test]
fn kat_typing_indicator() {
    assert_golden(
        &golden_typing(),
        33,
        "2a9bb74d921dfcf1863eadd79dd2041f21a51985f2c27d3f14d8b700cae8f576",
    );
}

#[test]
fn kat_presence() {
    assert_golden(
        &golden_presence(),
        1,
        "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
    );
}

#[test]
fn print_digests() {
    for (name, bytes) in [
        ("chat", golden_chat_message().to_bytes().unwrap()),
        ("delivery", golden_delivery_receipt().to_bytes().unwrap()),
        ("read", golden_read_receipt().to_bytes().unwrap()),
        ("typing", golden_typing().to_bytes().unwrap()),
        ("presence", golden_presence().to_bytes().unwrap()),
    ] {
        eprintln!("DIGEST {name} len={} sha={}", bytes.len(), digest(&bytes));
    }
}

// ── Band membership (SPEC §2, §4). ──

#[test]
fn all_ids_are_in_the_dig_chat_band_and_contiguous() {
    let ids = [
        ID_CHAT_MESSAGE,
        ID_DELIVERY_RECEIPT,
        ID_READ_RECEIPT,
        ID_TYPING_INDICATOR,
        ID_PRESENCE,
    ];
    assert_eq!(ids, CHAT_MESSAGE_TYPES);
    for (offset, id) in ids.iter().enumerate() {
        assert_eq!(id.band(), MessageBand::DigChat, "{id:?} in dig-chat band");
        assert_eq!(
            id.0,
            0x0000_0200 + offset as u32,
            "ids are contiguous from 0x0200"
        );
    }
    assert_eq!(ID_PRESENCE.0, 0x0000_0204);
}

// ── register_all → dispatch routing + duplicate refusal (SPEC §4). ──

/// A handler that records which method fired via a per-type counter.
#[derive(Default)]
struct CountingHandler {
    chat: AtomicU32,
    delivery: AtomicU32,
    read: AtomicU32,
    typing: AtomicU32,
    presence: AtomicU32,
}
impl ChatHandler for CountingHandler {
    fn on_chat_message(&self, _m: ChatMessage) -> Result<()> {
        self.chat.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_delivery_receipt(&self, _m: DeliveryReceipt) -> Result<()> {
        self.delivery.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_read_receipt(&self, _m: ReadReceipt) -> Result<()> {
        self.read.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_typing_indicator(&self, _m: TypingIndicator) -> Result<()> {
        self.typing.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_presence(&self, _m: Presence) -> Result<()> {
        self.presence.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn register_all_routes_each_id_to_the_right_decoded_kind() {
    let handler = Arc::new(CountingHandler::default());
    let mut registry = MessageRegistry::new();
    register_all(&mut registry, handler.clone()).unwrap();
    assert_eq!(registry.len(), 5);

    let cases: [(MessageType, Vec<u8>); 5] = [
        (ID_CHAT_MESSAGE, golden_chat_message().to_bytes().unwrap()),
        (
            ID_DELIVERY_RECEIPT,
            golden_delivery_receipt().to_bytes().unwrap(),
        ),
        (ID_READ_RECEIPT, golden_read_receipt().to_bytes().unwrap()),
        (ID_TYPING_INDICATOR, golden_typing().to_bytes().unwrap()),
        (ID_PRESENCE, golden_presence().to_bytes().unwrap()),
    ];
    for (id, payload) in &cases {
        registry
            .dispatch(*id, InteractionShape::OneShot, payload)
            .unwrap();
    }

    assert_eq!(handler.chat.load(Ordering::SeqCst), 1);
    assert_eq!(handler.delivery.load(Ordering::SeqCst), 1);
    assert_eq!(handler.read.load(Ordering::SeqCst), 1);
    assert_eq!(handler.typing.load(Ordering::SeqCst), 1);
    assert_eq!(handler.presence.load(Ordering::SeqCst), 1);
}

#[test]
fn register_all_refuses_duplicates() {
    let mut registry = MessageRegistry::new();
    register_all(&mut registry, Arc::new(CountingHandler::default())).unwrap();
    // A second registration collides on the very first id.
    let err = register_all(&mut registry, Arc::new(CountingHandler::default())).unwrap_err();
    assert_eq!(
        err,
        dig_message::MessageError::DuplicateType(ID_CHAT_MESSAGE.0)
    );
}

#[test]
fn register_all_is_additive_over_a_pre_populated_registry() {
    // Pre-register an unrelated peer-RPC-band handler, then add the chat layer additively.
    let mut registry = MessageRegistry::new();
    struct Ping;
    #[derive(chia_streamable_macro::Streamable, Debug, PartialEq, Eq)]
    struct PingPayload {
        nonce: u64,
    }
    impl dig_message::MessageKind for Ping {
        const TYPE_ID: MessageType = MessageType(dig_message::BAND_PEER_RPC);
        type Payload = PingPayload;
    }
    registry
        .register::<Ping, _>(|_: PingPayload| Ok(()))
        .unwrap();

    register_all(&mut registry, Arc::new(CountingHandler::default())).unwrap();
    assert_eq!(registry.len(), 6, "the pre-existing handler is undisturbed");
    assert!(registry.contains(MessageType(dig_message::BAND_PEER_RPC)));
}

// ── Unknown in-band id follows dig-message's unknown-type rule; never panics (SPEC §4). ──

#[test]
fn unknown_in_band_id_follows_the_unknown_type_rule() {
    let mut registry = MessageRegistry::new();
    register_all(&mut registry, Arc::new(CountingHandler::default())).unwrap();
    let unknown = MessageType(0x0000_02FF); // in the dig-chat band, but unallocated.
    assert_eq!(unknown.band(), MessageBand::DigChat);

    // A one-shot unknown is silently dropped (no panic, no error).
    assert_eq!(
        registry
            .dispatch(unknown, InteractionShape::OneShot, &[])
            .unwrap(),
        dig_message::Dispatch::Dropped
    );
    // A request-shaped unknown surfaces UNSUPPORTED_TYPE (no panic).
    assert_eq!(
        registry
            .dispatch(unknown, InteractionShape::Request, &[])
            .unwrap_err(),
        dig_message::MessageError::UnsupportedType(unknown.0)
    );
}

// ── DIGCHAT1 passthrough: arbitrary opaque envelope round-trips byte-identically (SPEC §1, §6). ──

#[test]
fn chat_message_round_trips_arbitrary_opaque_envelopes() {
    let envelopes: Vec<Vec<u8>> = vec![
        Vec::new(),                       // empty
        vec![0u8],                        // single byte
        seeded(b"random-blob", 1),        // tiny
        seeded(b"random-blob-2", 4096),   // large
        seeded(b"random-blob-3", 65_537), // > 64 KiB
    ];
    for env in envelopes {
        let msg = ChatMessage {
            message_id: b32(b"pt-mid"),
            envelope: env.clone(),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = ChatMessage::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.envelope, env,
            "opaque envelope must survive verbatim"
        );
        assert_eq!(decoded, msg);
    }
}

// ── Enum reject: an out-of-range discriminant decodes to a clean error, never a panic (SPEC §2). ──

#[test]
fn out_of_range_enum_discriminants_reject_cleanly() {
    // The struct still decodes (the wire is a plain u8); the typed accessor rejects the value.
    let bad_delivery = DeliveryReceipt {
        message_id: b32(b"x"),
        status: 200,
    };
    let bytes = bad_delivery.to_bytes().unwrap();
    let decoded = DeliveryReceipt::from_bytes(&bytes).unwrap();
    let err = decoded.status().unwrap_err();
    assert_eq!(err.value, 200);
    assert!(err.to_string().contains("DeliveryStatus"));

    assert!(TypingIndicator {
        conversation_id: b32(b"x"),
        state: 9
    }
    .state()
    .is_err());
    assert!(Presence { state: 250 }.state().is_err());

    // The valid discriminants decode to their variants.
    assert_eq!(DeliveryStatus::try_from(1).unwrap(), DeliveryStatus::Failed);
    assert_eq!(TypingState::try_from(1).unwrap(), TypingState::Stopped);
    assert_eq!(PresenceState::try_from(2).unwrap(), PresenceState::Offline);
    assert_eq!(
        DeliveryReceipt {
            message_id: b32(b"y"),
            status: 0
        }
        .status()
        .unwrap(),
        DeliveryStatus::Delivered
    );
    assert_eq!(
        TypingIndicator {
            conversation_id: b32(b"y"),
            state: 0
        }
        .state()
        .unwrap(),
        TypingState::Started
    );
    assert_eq!(
        Presence { state: 0 }.state().unwrap(),
        PresenceState::Online
    );
}
