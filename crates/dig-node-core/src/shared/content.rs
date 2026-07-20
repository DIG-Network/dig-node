//! The decoded-module wire type every content-producing/-consuming seam shares.
//!
//! `ContentResponse` is what the local-content seam decodes a `.dig` module into, and what the
//! peer-serving seam (`peer.rs`) transmits over the wire — the SAME shape both sides agree on, so
//! it lives in `shared/` rather than being owned by either seam (#1285 W1a).

/// A fully decoded content response: the merkle-verified bytes of one resource read, ready to
/// serve — either locally (content_serve) or over the peer wire (peer).
pub use digstore_core::wire::ContentResponse;
