//! # dig-chat-protocol — the DIG Network chat message-TYPE layer
//!
//! A PURE message-type layer riding the published [`dig_message`] base protocol. It defines the five
//! chat payload types in dig-message's reserved dig-chat band (`0x0000_0200..=0x0000_02FF`) and
//! registers them into a [`dig_message::MessageRegistry`]. That is the ENTIRE responsibility.
//!
//! ## What this crate deliberately does NOT do
//! - **No cryptography.** dig-message provides the outer e2e seal, the BLS sender signature, the
//!   anti-replay window, and the streaming state machine. This crate defines types only.
//! - **No content parsing.** [`ChatMessage::envelope`] is the OPAQUE `DIGCHAT1` content seal produced
//!   by the dig-chat application; this layer carries it verbatim and never inspects it. The protocol
//!   is therefore content-blind by construction — it cannot expose chat plaintext even in principle
//!   (SPEC §1, §6; NC-1).
//! - **No conversation/directory types.** A 1:1 conversation is correlation by peer DID and key
//!   resolution is a dig-node RPC — both out of scope for this one-shot message-type layer (SPEC §1).
//!
//! ## Using it
//! Implement [`ChatHandler`] and call [`register_all`] once on a [`dig_message::MessageRegistry`]; the
//! registry then decodes and routes each incoming chat type to the matching handler method. Unknown
//! in-band ids follow dig-message's unknown-type rule (never a panic).
//!
//! ```
//! use std::sync::Arc;
//! use dig_message::MessageRegistry;
//! use dig_chat_protocol::{register_all, ChatHandler, ChatMessage, DeliveryReceipt, Presence,
//!     ReadReceipt, TypingIndicator};
//!
//! struct Sink;
//! impl ChatHandler for Sink {
//!     fn on_chat_message(&self, _m: ChatMessage) -> dig_message::Result<()> { Ok(()) }
//!     fn on_delivery_receipt(&self, _m: DeliveryReceipt) -> dig_message::Result<()> { Ok(()) }
//!     fn on_read_receipt(&self, _m: ReadReceipt) -> dig_message::Result<()> { Ok(()) }
//!     fn on_typing_indicator(&self, _m: TypingIndicator) -> dig_message::Result<()> { Ok(()) }
//!     fn on_presence(&self, _m: Presence) -> dig_message::Result<()> { Ok(()) }
//! }
//!
//! let mut registry = MessageRegistry::new();
//! register_all(&mut registry, Arc::new(Sink)).unwrap();
//! assert_eq!(registry.len(), 5);
//! ```

#![forbid(unsafe_code)]

pub mod kinds;
pub mod types;

pub use kinds::{
    register_all, ChatHandler, ChatMessageKind, DeliveryReceiptKind, PresenceKind, ReadReceiptKind,
    TypingIndicatorKind, CHAT_MESSAGE_TYPES, ID_CHAT_MESSAGE, ID_DELIVERY_RECEIPT, ID_PRESENCE,
    ID_READ_RECEIPT, ID_TYPING_INDICATOR,
};
pub use types::{
    ChatEnumError, ChatMessage, DeliveryReceipt, DeliveryStatus, Presence, PresenceState,
    ReadReceipt, TypingIndicator, TypingState,
};
