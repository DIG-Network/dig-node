//! Seam 2 — DIG peer connectivity (#1285/#1303). Houses the [`PeerNetwork`] trait (the seam's
//! public surface — status/bring-up wiring for the standalone peer-network task and the control
//! surface, #1285 W1b-2), plus the peer-layer building blocks with no direct `Node` god-struct
//! coupling: networking (IPv6-first dial/bind), peer exchange, the content-location DHT, the
//! durable address book, and the identity-authenticated IPC session.
//!
//! `peer.rs` itself stays at the crate root: recon for W1b-2 found it carries no `impl Node`
//! methods (the peer-network god-struct methods actually lived in `lib.rs`, now carved into
//! [`PeerNetwork`]) — it is PeerStatus/session/framing types + free functions taking `Arc<Node>`
//! as a parameter, not `Node` methods. It's a candidate for a future zero-risk relocation
//! (matching W1b-0's pattern) but is out of scope for this trait carve.

pub mod address_book;
pub mod capsule_fallback;
pub mod dht;
pub mod net;
pub mod peer_network;
pub mod pex;
pub mod selector_adapter;
pub mod session;
pub mod union_locator;

pub(crate) use capsule_fallback::CapsuleFallbackLocator;
pub use peer_network::PeerNetwork;
pub(crate) use selector_adapter::SelectorAdapter;
pub(crate) use union_locator::{EmptyLocator, UnionLocator};
