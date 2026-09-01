//! The canonical JSON-RPC error envelope, minted from `dig-rpc-protocol`'s taxonomy.
//!
//! WIP (dig-node#340) — the mapping from dig-node's numeric codes onto
//! [`dig_rpc_protocol::ErrorCode`] lands next, so every emitted frame carries
//! `data.code` and `data.origin` by construction.
