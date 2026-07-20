//! Seam 5 — local content serving (W1b-0: module relocation only; the `ContentServer`
//! trait/handle carve lands in W1b-1). Houses content-serving building blocks that have
//! no direct `Node` god-struct coupling: the outgoing-bandwidth throttle and the
//! server-side verification ledger. `content_serve.rs` itself (the tangled `impl Node`
//! methods) stays at the crate root until W1b-1.

pub mod bandwidth;
pub mod verification_ledger;
