//! Paired-token authorization for the WALLET method surface (#370, SPEC §7.12).
//!
//! The pairing framework ([`crate::pairing`]) authorizes `control.*` mutations. The thin-client
//! model (epic #365) extends the SAME gate to the wallet methods: over the authorized loopback
//! surface, every wallet MUTATION and every custody-lifecycle method requires the master control
//! token OR a valid paired token; an unauthorized caller (no token / a wrong token / a revoked
//! token) is rejected with `-32030 UNAUTHORIZED` before the method runs. Wallet READ methods stay
//! open to local consumers (the read plane, §7.2).
//!
//! Gated wallet methods are ALSO never relayed upstream — a signing/custody request must never
//! leave the loopback node (the server enforces that, [`crate::server`]).
//!
//! This module is PURE (string classification + an allow/deny predicate) so the policy is
//! unit-tested exhaustively without a running server. The gated-mutation set mirrors the dig-wallet
//! Sage mutation surface (SPEC §18.9/§18.9a/§18.16/§18.17); it is kept in sync by SPEC §7.12 — a
//! mutation added to the wallet surface is added here.

use crate::control::ct_eq;

/// The custody-lifecycle namespace prefix (§18.20/§18.20a): `wallet.create`, `wallet.import`,
/// `wallet.restore`, `wallet.unlock`, `wallet.lock`, `wallet.status`, `wallet.list`,
/// `wallet.select`, `wallet.delete`. EVERY `wallet.*` method is gated by this prefix (even the reads
/// `wallet.status`/`wallet.list`, which reveal which wallets are custodied + their addresses), so a
/// new custody method is gated the moment it lands under `wallet.*` — no per-method allowlist.
pub const CUSTODY_PREFIX: &str = "wallet.";

/// Wallet MUTATION methods that MUST be authorized (§7.12): they sign, spend, broadcast, or change
/// persisted wallet state. Sourced from the dig-wallet Sage surface (§18.9/§18.9a/§18.16/§18.17).
const GATED_WALLET_MUTATIONS: &[&str] = &[
    // send/spend group (§18.9) — key-touching (sign_coin_spends signs; submit broadcasts).
    "send_xch",
    "bulk_send_xch",
    "send_cat",
    "bulk_send_cat",
    "combine",
    "split",
    "multi_send",
    "sign_coin_spends",
    "submit_transaction",
    // offer suite + DID/NFT mint & transfer (§18.9a).
    "make_offer",
    "take_offer",
    "combine_offers",
    "cancel_offer",
    "create_did",
    "bulk_mint_nfts",
    "transfer_nfts",
    "transfer_dids",
    // option contracts (§18.15).
    "mint_option",
    "transfer_options",
    "exercise_options",
    // state-changing record-update actions (§18.16).
    "resync_cat",
    "update_cat",
    "update_did",
    "update_option",
    "update_nft",
    "update_nft_collection",
    "redownload_nft",
    "increase_derivation_index",
    // network / peer / settings mutations (§18.17).
    "add_peer",
    "remove_peer",
    "set_discover_peers",
    "set_target_peers",
    "set_network",
    "set_network_override",
    "set_delta_sync",
    "set_delta_sync_override",
    "set_change_address",
    "save_user_theme",
    "delete_user_theme",
    // tipping subsystem mutations (#378, SPEC §18.23): they change persisted config or SPEND real
    // mainnet $DIG, so they require the master/paired token. The tip READS (`tip.get_config`,
    // `tip.get_ledger`) are open (the read plane, §7.2).
    "tip.set_config",
    "tip.manual",
    "tip.notify_consumed",
    "tip.dev_tick",
];

/// The authorization class of a JSON-RPC method w.r.t. the wallet surface (§7.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletMethodClass {
    /// A custody-lifecycle method (`wallet.*`, §18.20) — GATED.
    Custody,
    /// A wallet MUTATION (sign/spend/offer/mint/transfer + state-changing actions) — GATED.
    Mutation,
    /// Not a gated wallet method — a wallet READ, a `control.*`/`pairing.*`/`dig.*`/`cache.*`
    /// method, or anything else. This gate leaves it alone (the read plane and the control gate
    /// apply their own policy).
    Other,
}

/// Classify a method against the wallet-authorization policy. PURE.
pub fn classify(method: &str) -> WalletMethodClass {
    if method.starts_with(CUSTODY_PREFIX) {
        WalletMethodClass::Custody
    } else if GATED_WALLET_MUTATIONS.contains(&method) {
        WalletMethodClass::Mutation
    } else {
        WalletMethodClass::Other
    }
}

/// Whether `method` requires the master or a paired token over the authorized surface (§7.12) —
/// true for every custody-lifecycle and wallet-mutation method.
pub fn requires_authorization(method: &str) -> bool {
    matches!(
        classify(method),
        WalletMethodClass::Custody | WalletMethodClass::Mutation
    )
}

/// Decide whether a wallet-surface call is AUTHORIZED. PURE.
///
/// - A method that does NOT require authorization (a read / non-wallet method) is always
///   authorized here — other gates (the read plane, the `control.*` gate) apply their own policy.
/// - A GATED (custody/mutation) method is authorized ONLY when the presented token is the master
///   control token (constant-time) OR a valid paired token (`is_paired`). No token → denied.
///
/// `is_paired` is injected so this stays pure + unit-testable without the on-disk paired-token
/// store; the server passes [`crate::pairing::is_paired_token`].
pub fn authorize(
    method: &str,
    presented: Option<&str>,
    master: &str,
    is_paired: impl Fn(&str) -> bool,
) -> bool {
    if !requires_authorization(method) {
        return true;
    }
    match presented {
        Some(tok) => ct_eq(tok, master) || is_paired(tok),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "master-token-value";
    const PAIRED: &str = "paired-token-value";

    /// A stand-in paired-token store: `PAIRED` is valid, everything else (incl. a revoked token) is not.
    fn is_paired(tok: &str) -> bool {
        tok == PAIRED
    }

    #[test]
    fn custody_methods_are_gated() {
        for m in [
            "wallet.create",
            "wallet.import",
            "wallet.restore",
            "wallet.unlock",
            "wallet.lock",
            "wallet.status",
            "wallet.list",
            "wallet.select",
            "wallet.delete",
        ] {
            assert_eq!(classify(m), WalletMethodClass::Custody, "{m}");
            assert!(requires_authorization(m), "{m} must be gated");
        }
    }

    #[test]
    fn spend_sign_and_offer_methods_are_gated_mutations() {
        for m in [
            "send_xch",
            "send_cat",
            "sign_coin_spends",
            "submit_transaction",
            "make_offer",
            "take_offer",
            "create_did",
            "bulk_mint_nfts",
            "transfer_nfts",
        ] {
            assert_eq!(classify(m), WalletMethodClass::Mutation, "{m}");
            assert!(requires_authorization(m), "{m} must be gated");
        }
    }

    #[test]
    fn reads_and_non_wallet_methods_are_not_gated() {
        for m in [
            "get_coins",
            "get_sync_status",
            "view_coin_spends",
            "view_offer",
            "check_address",
            "login",
            "dig.getContent",
            "cache.getConfig",
            "control.status",
            "pairing.request",
            "rpc.discover",
        ] {
            assert_eq!(classify(m), WalletMethodClass::Other, "{m}");
            assert!(!requires_authorization(m), "{m} must not be gated here");
        }
    }

    #[test]
    fn unpaired_caller_is_denied_on_every_gated_method() {
        // No token, a wrong token, and a revoked token are all denied for every mutation + custody.
        for m in GATED_WALLET_MUTATIONS.iter().copied().chain([
            "wallet.create",
            "wallet.unlock",
            "wallet.delete",
        ]) {
            assert!(!authorize(m, None, MASTER, is_paired), "{m}: no token");
            assert!(
                !authorize(m, Some("wrong-token"), MASTER, is_paired),
                "{m}: wrong token"
            );
            assert!(
                !authorize(m, Some("revoked-token-not-in-store"), MASTER, is_paired),
                "{m}: revoked token"
            );
        }
    }

    #[test]
    fn tip_mutations_are_gated_and_tip_reads_are_open() {
        // Money-spending / state-changing tip methods are gated (#378).
        for m in [
            "tip.set_config",
            "tip.manual",
            "tip.notify_consumed",
            "tip.dev_tick",
        ] {
            assert_eq!(classify(m), WalletMethodClass::Mutation, "{m}");
            assert!(requires_authorization(m), "{m} must be gated");
            assert!(
                !authorize(m, None, MASTER, is_paired),
                "{m}: no token denied"
            );
            assert!(
                authorize(m, Some(PAIRED), MASTER, is_paired),
                "{m}: paired ok"
            );
        }
        // Tip reads follow the read plane — open.
        for m in ["tip.get_config", "tip.get_ledger"] {
            assert_eq!(classify(m), WalletMethodClass::Other, "{m}");
            assert!(!requires_authorization(m), "{m} is a read");
        }
    }

    #[test]
    fn master_or_paired_token_authorizes_a_gated_mutation() {
        assert!(authorize("send_xch", Some(MASTER), MASTER, is_paired));
        assert!(authorize("send_xch", Some(PAIRED), MASTER, is_paired));
        assert!(authorize("wallet.unlock", Some(PAIRED), MASTER, is_paired));
    }

    #[test]
    fn a_read_is_authorized_without_a_token() {
        assert!(authorize("get_coins", None, MASTER, is_paired));
        assert!(authorize("dig.getContent", None, MASTER, is_paired));
    }
}
