//! Binding the five chat payloads to `dig-message`'s type registry (SPEC §4).
//!
//! Each payload declares a [`MessageKind`] whose `TYPE_ID` is its reserved id in the dig-chat band
//! (`0x0000_0200..=0x0000_02FF`) and whose `Payload` is the Streamable struct from [`crate::types`].
//! The ids are contiguous from [`BAND_DIG_CHAT`] and additive-only: an id, once assigned, is never
//! renumbered or repurposed (SPEC §2, §4).
//!
//! [`register_all`] wires all five into a [`MessageRegistry`] against a caller-supplied
//! [`ChatHandler`]. It refuses duplicates by surfacing dig-message's [`MessageError::DuplicateType`]
//! (never overwriting an existing handler), and it leaves dig-message's unknown-type rule intact — an
//! unregistered in-band id (e.g. `0x02FF`) dispatches per [`MessageRegistry::dispatch`]
//! (UNSUPPORTED_TYPE for a request/stream shape, a silent drop for a one-shot/response; never a panic).

use std::sync::Arc;

use dig_message::{MessageKind, MessageRegistry, MessageType, Result, BAND_DIG_CHAT};

use crate::types::{ChatMessage, DeliveryReceipt, Presence, ReadReceipt, TypingIndicator};

/// The reserved id for [`ChatMessage`] (SPEC §2).
pub const ID_CHAT_MESSAGE: MessageType = MessageType(BAND_DIG_CHAT);
/// The reserved id for [`DeliveryReceipt`] (SPEC §2).
pub const ID_DELIVERY_RECEIPT: MessageType = MessageType(BAND_DIG_CHAT + 1);
/// The reserved id for [`ReadReceipt`] (SPEC §2).
pub const ID_READ_RECEIPT: MessageType = MessageType(BAND_DIG_CHAT + 2);
/// The reserved id for [`TypingIndicator`] (SPEC §2).
pub const ID_TYPING_INDICATOR: MessageType = MessageType(BAND_DIG_CHAT + 3);
/// The reserved id for [`Presence`] (SPEC §2).
pub const ID_PRESENCE: MessageType = MessageType(BAND_DIG_CHAT + 4);

/// The [`MessageKind`] for [`ChatMessage`] (id `0x0200`).
pub struct ChatMessageKind;
impl MessageKind for ChatMessageKind {
    const TYPE_ID: MessageType = ID_CHAT_MESSAGE;
    type Payload = ChatMessage;
}

/// The [`MessageKind`] for [`DeliveryReceipt`] (id `0x0201`).
pub struct DeliveryReceiptKind;
impl MessageKind for DeliveryReceiptKind {
    const TYPE_ID: MessageType = ID_DELIVERY_RECEIPT;
    type Payload = DeliveryReceipt;
}

/// The [`MessageKind`] for [`ReadReceipt`] (id `0x0202`).
pub struct ReadReceiptKind;
impl MessageKind for ReadReceiptKind {
    const TYPE_ID: MessageType = ID_READ_RECEIPT;
    type Payload = ReadReceipt;
}

/// The [`MessageKind`] for [`TypingIndicator`] (id `0x0203`).
pub struct TypingIndicatorKind;
impl MessageKind for TypingIndicatorKind {
    const TYPE_ID: MessageType = ID_TYPING_INDICATOR;
    type Payload = TypingIndicator;
}

/// The [`MessageKind`] for [`Presence`] (id `0x0204`).
pub struct PresenceKind;
impl MessageKind for PresenceKind {
    const TYPE_ID: MessageType = ID_PRESENCE;
    type Payload = Presence;
}

/// The five reserved dig-chat ids, in contiguous order from [`BAND_DIG_CHAT`] (SPEC §2). Useful for
/// tests and for enumerating the layer's surface.
pub const CHAT_MESSAGE_TYPES: [MessageType; 5] = [
    ID_CHAT_MESSAGE,
    ID_DELIVERY_RECEIPT,
    ID_READ_RECEIPT,
    ID_TYPING_INDICATOR,
    ID_PRESENCE,
];

/// The application's handlers for each decoded chat payload (SPEC §4). A consumer implements this once
/// and passes it to [`register_all`]; the registry decodes the on-wire bytes into the typed payload
/// before invoking the matching method. Each method returns [`Result`] so a handler-side failure
/// propagates through dispatch unchanged.
pub trait ChatHandler: Send + Sync + 'static {
    /// Handle a decoded [`ChatMessage`] (its `envelope` is still the opaque `DIGCHAT1` seal).
    fn on_chat_message(&self, message: ChatMessage) -> Result<()>;
    /// Handle a decoded [`DeliveryReceipt`].
    fn on_delivery_receipt(&self, receipt: DeliveryReceipt) -> Result<()>;
    /// Handle a decoded [`ReadReceipt`].
    fn on_read_receipt(&self, receipt: ReadReceipt) -> Result<()>;
    /// Handle a decoded [`TypingIndicator`].
    fn on_typing_indicator(&self, indicator: TypingIndicator) -> Result<()>;
    /// Handle a decoded [`Presence`] announcement.
    fn on_presence(&self, presence: Presence) -> Result<()>;
}

/// Register all five chat message types into `registry`, dispatching each to `handler` (SPEC §4).
///
/// Registration is additive: the five ids are added without disturbing any pre-existing handlers, and
/// any id already present makes the whole call fail rather than overwrite.
///
/// # Errors
/// [`MessageError::DuplicateType`](dig_message::MessageError::DuplicateType) if any of the five ids is
/// already registered (SPEC §4 additive-only). On error, ids registered earlier in the call remain —
/// registration is not transactional; call it once on a fresh registry.
pub fn register_all(registry: &mut MessageRegistry, handler: Arc<dyn ChatHandler>) -> Result<()> {
    let h = Arc::clone(&handler);
    registry.register::<ChatMessageKind, _>(move |m| h.on_chat_message(m))?;
    let h = Arc::clone(&handler);
    registry.register::<DeliveryReceiptKind, _>(move |m| h.on_delivery_receipt(m))?;
    let h = Arc::clone(&handler);
    registry.register::<ReadReceiptKind, _>(move |m| h.on_read_receipt(m))?;
    let h = Arc::clone(&handler);
    registry.register::<TypingIndicatorKind, _>(move |m| h.on_typing_indicator(m))?;
    registry.register::<PresenceKind, _>(move |m| handler.on_presence(m))?;
    Ok(())
}
