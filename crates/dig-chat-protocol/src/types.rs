//! The five chat payload types (SPEC §2) and their status/state enums.
//!
//! Each payload is a Chia-[`Streamable`](chia_traits::Streamable) struct so its bytes are byte-
//! deterministic across every target (SPEC §3) — the derive lays the fields out in declaration order
//! with no padding or self-describing tags, exactly as `dig-message`'s own payloads do.
//!
//! ## Content-blindness (the load-bearing property, SPEC §1, §6)
//! The ONLY content-bearing field in the whole layer is [`ChatMessage::envelope`]: an OPAQUE
//! `DIGCHAT1` blob sealed by the dig-chat application to the recipient's key. This crate NEVER parses
//! it — it carries the bytes verbatim, so the protocol layer cannot expose chat plaintext even in
//! principle. Receipts, typing, and presence carry only ids and small enum discriminants (metadata).
//!
//! ## Enums vs. the wire (SPEC §2)
//! `status`/`state` are `u8` ON THE WIRE (a fixed-width, forward-compatible discriminant) but are
//! surfaced as real Rust enums via [`TryFrom<u8>`]. An unknown discriminant is rejected as
//! [`ChatEnumError`] — a clean, typed error — and NEVER panics, upholding dig-message's fail-cleanly
//! rule for anything read off the wire.

use chia_protocol::Bytes32;
use chia_streamable_macro::Streamable;

/// An unrecognized `status`/`state` discriminant read off the wire (SPEC §2). Surfaced as a clean
/// error — decoding a chat enum NEVER panics on an out-of-range byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatEnumError {
    /// The name of the enum that rejected the value (for a legible message).
    pub enum_name: &'static str,
    /// The out-of-range discriminant that was read.
    pub value: u8,
}

impl core::fmt::Display for ChatEnumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "unrecognized {} discriminant {}",
            self.enum_name, self.value
        )
    }
}

impl std::error::Error for ChatEnumError {}

/// Declare a `u8`-wire enum with an exhaustive [`TryFrom<u8>`] that rejects unknown values cleanly.
///
/// The wire always carries the raw `u8`; this enum is the typed, validated view of it. Adding a new
/// variant is additive (a new discriminant) and never renumbers an existing one (SPEC §2 additive-only).
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $value:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $value ),+
        }

        impl $name {
            /// This variant's on-wire `u8` discriminant.
            #[must_use]
            pub fn as_u8(self) -> u8 {
                self as u8
            }
        }

        impl TryFrom<u8> for $name {
            type Error = ChatEnumError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( $value => Ok(Self::$variant), )+
                    other => Err(ChatEnumError { enum_name: stringify!($name), value: other }),
                }
            }
        }
    };
}

wire_enum! {
    /// The delivery outcome carried in [`DeliveryReceipt::status`] (SPEC §2, id `0x0201`).
    pub enum DeliveryStatus {
        /// The message reached the recipient's node.
        Delivered = 0,
        /// Delivery failed (undeliverable / rejected).
        Failed = 1,
    }
}

wire_enum! {
    /// The typing transition carried in [`TypingIndicator::state`] (SPEC §2, id `0x0203`).
    pub enum TypingState {
        /// The peer began composing.
        Started = 0,
        /// The peer stopped composing.
        Stopped = 1,
    }
}

wire_enum! {
    /// The presence state carried in [`Presence::state`] (SPEC §2, id `0x0204`).
    pub enum PresenceState {
        /// The peer is online and reachable.
        Online = 0,
        /// The peer is idle / away.
        Away = 1,
        /// The peer is offline.
        Offline = 2,
    }
}

/// A chat message (SPEC §2, id `0x0200`). The `envelope` is the OPAQUE `DIGCHAT1` content seal — the
/// sole content-bearing field, carried verbatim and never parsed by this layer (SPEC §1, §6).
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct ChatMessage {
    /// The application-assigned message id that receipts (`0x0201`/`0x0202`) reference.
    pub message_id: Bytes32,
    /// The opaque `DIGCHAT1` sealed content blob (SPEC §4 of the dig-chat app spec). Never parsed here.
    pub envelope: Vec<u8>,
}

/// A delivery receipt (SPEC §2, id `0x0201`) acknowledging that a [`ChatMessage`] was (or was not)
/// delivered. `status` is a [`DeliveryStatus`] on the wire as a `u8`.
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct DeliveryReceipt {
    /// The [`ChatMessage::message_id`] this receipt refers to.
    pub message_id: Bytes32,
    /// The delivery outcome as a [`DeliveryStatus`] discriminant.
    pub status: u8,
}

impl DeliveryReceipt {
    /// The typed delivery outcome.
    ///
    /// # Errors
    /// [`ChatEnumError`] if `status` is not a recognized [`DeliveryStatus`] discriminant.
    pub fn status(&self) -> Result<DeliveryStatus, ChatEnumError> {
        DeliveryStatus::try_from(self.status)
    }
}

/// A read receipt (SPEC §2, id `0x0202`) acknowledging that a [`ChatMessage`] was read.
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct ReadReceipt {
    /// The [`ChatMessage::message_id`] that was read.
    pub message_id: Bytes32,
}

/// A typing indicator (SPEC §2, id `0x0203`) for a conversation. `state` is a [`TypingState`] on the
/// wire as a `u8`.
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct TypingIndicator {
    /// The conversation this indicator applies to (a 1:1 conversation is correlation by peer DID).
    pub conversation_id: Bytes32,
    /// The typing transition as a [`TypingState`] discriminant.
    pub state: u8,
}

impl TypingIndicator {
    /// The typed typing transition.
    ///
    /// # Errors
    /// [`ChatEnumError`] if `state` is not a recognized [`TypingState`] discriminant.
    pub fn state(&self) -> Result<TypingState, ChatEnumError> {
        TypingState::try_from(self.state)
    }
}

/// A presence announcement (SPEC §2, id `0x0204`). `state` is a [`PresenceState`] on the wire as a `u8`.
#[derive(Debug, Clone, PartialEq, Eq, Streamable)]
pub struct Presence {
    /// The presence state as a [`PresenceState`] discriminant.
    pub state: u8,
}

impl Presence {
    /// The typed presence state.
    ///
    /// # Errors
    /// [`ChatEnumError`] if `state` is not a recognized [`PresenceState`] discriminant.
    pub fn state(&self) -> Result<PresenceState, ChatEnumError> {
        PresenceState::try_from(self.state)
    }
}
