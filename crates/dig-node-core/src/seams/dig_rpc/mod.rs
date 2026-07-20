//! Seam 4 — dig RPC server (#1285/#1303). Houses the [`RpcDispatch`] trait (the seam's public
//! surface — the node-internal JSON-RPC dispatch, carved unchanged from `lib.rs`'s `handle_rpc`,
//! #1285 W1b-5). The `dig-rpc-protocol` crate ADOPTION (replacing the hand-rolled match with the
//! shared contract crate's dispatcher) is W3 — out of scope here.

mod dispatch;

pub use dispatch::RpcDispatch;
