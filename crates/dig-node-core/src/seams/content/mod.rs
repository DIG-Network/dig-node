//! Seam 5 — local content serving (#1285/#1303). Houses the [`ContentServer`] trait (the
//! seam's public surface — serve/manifest/generation lookups over the loopback plaintext
//! path), the outgoing-bandwidth throttle, and the server-side verification ledger.
//!
//! `ContentServer` is implemented by [`crate::Node`] with its EXISTING method bodies
//! (carved from `content_serve.rs` unchanged, #1285 W1b-1) — this is a behaviour-preserving
//! trait extraction, not a new implementation. The trait is `async_trait`-boxed (matching
//! `crate::shared::AnchoredRootResolver`'s pattern) so it stays dyn-compatible for the
//! `Arc<dyn ContentServer>` handle the W1c composition root will hold.

pub mod bandwidth;
pub mod content_serve;
pub mod verification_ledger;

pub use content_serve::ContentServer;
