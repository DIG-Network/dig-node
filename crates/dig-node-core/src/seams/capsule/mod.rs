//! Seam 6 — capsule management (#1285/#1303). Houses the [`CapsuleStore`] trait (the seam's
//! public surface — list/remove/fetch/gap-fill/backfill the on-disk `.dig` capsule cache,
//! carved unchanged from `lib.rs`/`download.rs`, #1285 W1b-4). The concrete `.dig` format
//! reader/writer stays external (`digstore-core`); this seam is the NODE's cache-management
//! surface over it.

mod capsule_store;

pub use capsule_store::CapsuleStore;
