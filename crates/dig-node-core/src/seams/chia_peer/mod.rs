//! Seam 1 — Chia peer connectivity (#1285/#1286/#1303). Houses the [`ChainSource`] trait (the
//! seam's boundary — how the node reaches the CHIA chain for anchored-root resolution) and its
//! production implementation, [`CoinsetResolver`], relocated unchanged from `lib.rs` (#1285
//! W1b-3).
//!
//! The shared [`crate::shared::chain_view::AnchoredRootResolver`] trait + `AnchoredStoreState`
//! (extracted in W1a) STAY in `shared/` — that is the cross-seam vocabulary every seam reads a
//! chain-anchored root through (the content-serve pin, the chain-watch gap-filler). `ChainSource`
//! is this seam's OWN boundary: it composes/exposes the shared resolver rather than duplicating
//! its contract, so `Node` (implementing `ChainSource`) hands out the SAME `Arc<dyn
//! AnchoredRootResolver>` every other seam already consumes.

mod coinset_resolver;
pub mod light_client;

pub use coinset_resolver::CoinsetResolver;
pub(crate) use coinset_resolver::{default_anchored_resolver, resolution_coinset};

pub use light_client::{
    confirmation_depth, connect_light_client, register_light_client_provider, submit_spend,
    ChiaPeerSubscriptions, CHIA_PEER_INDEPENDENCE_GROUP,
};

use std::sync::Arc;

use crate::shared::chain_view::AnchoredRootResolver;
use crate::Node;

/// Seam 1's public surface — the node's route to the CHIA-anchored root source. `async_trait`-free
/// (a plain `Arc` accessor, not an async operation) but `Send + Sync` so it stays dyn-compatible
/// for the future `Arc<dyn ChainSource>` handle (W1c), matching the other seam traits' pattern.
pub trait ChainSource: Send + Sync {
    /// The node's anchored-root resolver (the trusted-root source for the read-path pin AND the
    /// chain-watch loop). Cloned `Arc` so every consumer shares the SAME resolver — production
    /// coinset walk ([`CoinsetResolver`]), or a deterministic one in tests.
    fn anchored_root_resolver_arc(&self) -> Arc<dyn AnchoredRootResolver>;
}

impl ChainSource for Node {
    fn anchored_root_resolver_arc(&self) -> Arc<dyn AnchoredRootResolver> {
        self.anchored_root_resolver.clone()
    }
}
