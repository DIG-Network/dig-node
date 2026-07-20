//! Seam 2 — DIG peer connectivity (W1b-0: module relocation only; the `PeerNetwork`
//! trait/handle carve lands in W1b-2). Houses the peer-layer building blocks that have
//! no direct `Node` god-struct coupling: networking (IPv6-first dial/bind), peer exchange,
//! the content-location DHT, the durable address book, and the identity-authenticated
//! IPC session. `peer.rs` itself (the tangled `impl Node` methods) stays at the crate
//! root until W1b-2.

pub mod address_book;
pub mod dht;
pub mod net;
pub mod pex;
pub mod session;
