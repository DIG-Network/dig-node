//! # `sage` — the Sage-parity wallet RPC (#205 phase 2)
//!
//! A byte-compatible replica of the [Sage](https://github.com/xch-dev/sage) wallet
//! RPC surface (`endpoints.json`, pinned to **v0.12.11**) backed by a **direct-peer
//! chain-sync** into a **local SQLite wallet DB**, with the `chia-query`/coinset.org
//! **fallback tier** for the syncing + out-of-DB/non-wallet cases. This is the
//! release-first foundation the DIG browser extension (#205 phase 3) consumes.
//!
//! ## Layers (see `SPEC.md §18` + `docs/design/dig-node-sage-parity-rpc.md`)
//!
//! - [`types`] — the Sage wire types (the `endpoints.json` request/response shapes).
//!   Byte-parity is a contract: `Amount` number/string threshold, snake_case, optional
//!   omission. This is what a Sage RPC client sees.
//! - [`db`] — the local SQLite wallet DB (coins/CATs/NFTs/DIDs/txns + synced peak).
//!   The source of truth for a *synced* wallet's data (design B.6).
//! - [`sync`] — the direct-peer subscription sync loop on `chia-wallet-sdk` `Peer`
//!   (`request_puzzle_state(subscribe=true)` + `coin_state_update`), persisting into
//!   [`db`], with reorg rollback (design B.3).
//! - [`fallback`] — the [`fallback::ChainFallback`] tier (design B.5): `chia-query`
//!   reused as-is (coinset.org + non-subscribing peer point-reads). Used ONLY while
//!   syncing or for out-of-DB/non-wallet reads — never the primary path.
//! - [`routing`] — the sync-state-gated source selection (design B.6 routing table).
//! - [`rpc`] — the `POST /{method}` handler set + Sage's text-body error model (A.3),
//!   dispatching every served method.
//! - [`spend`] — the send/spend group builders (#216): XCH/CAT sends, combine/split,
//!   sign/view/submit — build via `chia-wallet-sdk`, validate via `dig-clvm`, broadcast
//!   via the [`spend::Broadcaster`] gate (never in CI).
//! - [`mint`] — DID/NFT mint + transfer builders (#218): `create_did`, `bulk_mint_nfts`,
//!   `transfer_nfts`, `transfer_dids`.
//! - [`offers`] — the offer suite builders (#218): `make_offer`, `take_offer`,
//!   `view_offer`, `combine_offers`, `cancel_offer` (`get_offers`/`get_offer` are DB reads).
//! - [`transport`] — the dual transport (design C.3): mTLS `9257` (Sage byte-parity)
//!   + the plain-HTTP+CORS browser mirror, both dispatching the SAME handler set.
//!
//! - [`events`] — the [`events::SyncEvent`] stream (design A.9, #205 PR4): an in-process
//!   [`events::EventBus`] the sync loop publishes to, streamed over `GET /events` (SSE) on
//!   the shared transport. `get_sync_status` polling remains fully supported.
//! - [`actions`] — the record-update actions (#205 PR4): `resync_cat`, `update_cat`,
//!   `update_did`, `update_option`, `update_nft`, `update_nft_collection`, `redownload_nft`,
//!   `increase_derivation_index`.
//! - [`themes`] — the Sage-desktop-UI theme store (#205 PR4): `get_user_themes`,
//!   `get_user_theme`, `save_user_theme`, `delete_user_theme` (DB-backed, additive).
//! - [`network`] — peers + network/sync settings (#205 PR4): `get_peers`/`add_peer`/
//!   `remove_peer`, `set_discover_peers`/`set_target_peers`, `set_network`/
//!   `set_network_override`/`get_networks`/`get_network`, `set_delta_sync`/
//!   `set_delta_sync_override`, `set_change_address`.
//! - [`options`] — the option-contract suite (#205 PR4): `get_options`/`get_option` (DB
//!   reads), `mint_option`/`transfer_options` (real `chia-wallet-sdk` `OptionLauncher`/
//!   `OptionContract` builders, XCH/CAT scope). `exercise_options` is a documented follow-on
//!   (see the module docs) pending underlying-lock-coin lineage tracking.
//!
//! ## Scope
//!
//! The generated-OpenAPI conformance vector (SPEC §18.19) IS committed (`sage-cli` — a pure
//! CLI/RPC crate with no Tauri/desktop dependency — was built from the pinned `v0.12.11` tag
//! and `sage rpc generate_openapi` run once; no build step is needed to re-derive it).
//! `exercise_options` (above) remains the one option-suite method pending underlying-lock-coin
//! lineage tracking (SPEC §18.15); real image-derived theme content remains pending an
//! image/color-extraction pipeline (SPEC §18.16).

pub mod actions;
pub mod custody;
pub mod db;
pub mod events;
pub mod fallback;
pub mod mint;
pub mod network;
pub mod offers;
pub mod options;
pub mod routing;
pub mod rpc;
pub mod singleton;
pub mod spend;
pub mod sync;
pub mod themes;
pub mod transport;
pub mod types;

use std::fmt;

/// Sage's error-kind → HTTP-status model (design A.3). A Sage RPC client expects a
/// non-200 status with the error message as a **plain-text** body (NOT a JSON error
/// object), so the dig-node replica reproduces that mapping byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad request / malformed input → `400`.
    Api,
    /// Requested entity not found → `404`.
    NotFound,
    /// Not authorized (secret-touching endpoint from a non-authorized origin) → `401`.
    Unauthorized,
    /// Wallet/internal/database failure → `500`.
    Internal,
}

impl ErrorKind {
    /// The HTTP status code Sage maps this kind to (design A.3).
    pub fn status(self) -> u16 {
        match self {
            ErrorKind::Api => 400,
            ErrorKind::NotFound => 404,
            ErrorKind::Unauthorized => 401,
            ErrorKind::Internal => 500,
        }
    }
}

/// A Sage-parity error: a [`kind`](ErrorKind) (→ HTTP status) plus a display message
/// (→ the plain-text response body).
#[derive(Debug, Clone)]
pub struct Error {
    /// The error kind driving the HTTP status.
    pub kind: ErrorKind,
    /// The human-readable message; serialized verbatim as the response body.
    pub message: String,
}

impl Error {
    /// A `400 Bad Request` (malformed request / invalid argument).
    pub fn api(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Api,
            message: message.into(),
        }
    }
    /// A `404 Not Found`.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::NotFound,
            message: message.into(),
        }
    }
    /// A `401 Unauthorized` (secret-touching endpoint reached from a disallowed origin).
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Unauthorized,
            message: message.into(),
        }
    }
    /// A `500 Internal Server Error` (wallet/db/internal failure).
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::internal(format!("wallet db: {e}"))
    }
}

/// The Sage-parity result alias used across the surface.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn kind_status_matches_sage_a3_table() {
        assert_eq!(ErrorKind::Api.status(), 400);
        assert_eq!(ErrorKind::NotFound.status(), 404);
        assert_eq!(ErrorKind::Unauthorized.status(), 401);
        assert_eq!(ErrorKind::Internal.status(), 500);
    }

    #[test]
    fn error_body_is_the_plain_message() {
        let e = Error::not_found("no such nft");
        assert_eq!(e.to_string(), "no such nft");
        assert_eq!(e.kind.status(), 404);
    }
}
