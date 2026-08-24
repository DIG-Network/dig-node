//! Cross-seam shared vocabulary (#1285 W1a).
//!
//! `shared/` is the ONLY vocabulary the node's seams (peer, wallet, rpc, local-content, capsule,
//! chain, key-management) are allowed to share — every seam talks to every other seam through
//! these types alone, never by reaching into another seam's internals. W1a is a pure,
//! behaviour-preserving MOVE of the types/functions that already crossed seam boundaries before
//! this module existed; it introduces no new types (id newtypes like `StoreId`/`CapsuleId` are
//! deferred to a later wave, once a seam trait actually needs them).
//!
//! - [`at_rest`] — the at-rest decision primitives every seam that mints key material shares:
//!   [`presence`] (an unreadable path is NOT an absent one) and [`write_new_owner_only`] /
//!   atomic create-new that makes two concurrent starts safe).
//! - [`chain_view`] — the injectable on-chain root resolver ([`AnchoredRootResolver`],
//!   [`AnchoredStoreState`]) the read-path pin and the chain-watch loop both depend on.
//! - [`content`] — the decoded-module wire type ([`ContentResponse`]) the local-content and
//!   peer-serving paths both produce/consume.
//! - [`identity`] — the node's persistent mTLS machine identity ([`load_or_generate_node_cert`])
//!   and the one-time TLS crypto-provider install ([`install_crypto_provider`]), needed by both
//!   the peer-network transport and any seam that dials/serves mTLS (e.g. DHT bootstrap tests).
//! - [`panic_guard`] — the [`catch_iteration`](panic_guard::catch_iteration) combinator every
//!   long-lived background loop wraps its per-iteration body in, so a single iteration's panic can
//!   never silently kill a whole subsystem for the process's lifetime (#2067).

pub mod at_rest;
pub mod chain_view;
pub mod content;
pub mod identity;
pub mod panic_guard;

pub use at_rest::{presence, write_new_owner_only, Presence};
pub use chain_view::{AnchoredRootResolver, AnchoredStoreState};
pub use content::ContentResponse;
pub use identity::{install_crypto_provider, load_or_generate_node_cert};
pub(crate) use panic_guard::catch_iteration;
