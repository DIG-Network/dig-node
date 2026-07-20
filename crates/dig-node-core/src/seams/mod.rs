//! The 7 architecturally-separated seams (dig-node epic #1285/#1303). Each seam is its
//! own module boundary; seams communicate ONLY through `crate::shared` types — never by
//! reaching into another seam's internals. This module tree is populated incrementally
//! across the W1b sub-PR sequence (see #1285); a seam not yet listed here still lives at
//! the crate root pending its carve.

pub mod chia_peer;
pub mod content;
pub mod dig_peer;
