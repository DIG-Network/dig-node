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
// The self-verifying tier-0 preimage resolver (#2033, PR-2). Its surface is exercised by its own
// tests but not yet CALLED by production code — the tier-0 fetch loop wires it in PR-3 — so the
// as-yet-unconsumed client + resolver would otherwise trip `dead_code`. The allow is removed when
// PR-3 constructs it.
#[allow(dead_code)]
pub mod capsule_resolver;
pub mod dht;
pub mod forwarded_ask;
pub mod holdings;
pub mod module_anchor;
pub mod module_reshare;
pub mod module_serve;
pub mod module_transport;
pub mod neighbourhood_probe;
pub mod net;
pub mod peer_network;
pub mod pex;
pub mod ping;
pub mod pool_locator;
pub mod profile_sync;
/// Wire-level range-stream conformance tests (#1668): the real serve path over a real loopback mTLS
/// connection, decoded through the real dig-nat codec. Test-only — there is no production surface here.
#[cfg(test)]
mod range_stream_wire;
pub mod resolve_capsule;
pub mod selector_adapter;
pub mod self_excluding_locator;
pub mod serve_log;
pub mod session;
pub mod store_melted;
pub mod union_locator;

pub(crate) use capsule_fallback::CapsuleFallbackLocator;
pub(crate) use forwarded_ask::{
    ForwardedAsk, NatForwardedAsk, MAX_CONCURRENT_FORWARDED_ASKS,
};
pub use module_anchor::ChainAnchoredModuleVerifier;
pub(crate) use module_reshare::DEFAULT_MAX_CONCURRENT_WARMS;
pub use module_reshare::{
    spawn_capsule_warm, AnnounceHolder, CapsuleWarmer, WarmFailure, WarmOutcome, WarmPaths,
    WarmRegistry,
};
pub use module_transport::NatModuleTransport;
pub use peer_network::PeerNetwork;
pub(crate) use pool_locator::{ConnectedPool, PoolProviderLocator};
pub(crate) use selector_adapter::SelectorAdapter;
pub(crate) use self_excluding_locator::{retain_excluding_self, SelfExcludingLocator};
pub(crate) use union_locator::{EmptyLocator, UnionLocator};
