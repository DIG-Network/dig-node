//! Paired-token authorization for the WALLET method surface (#370, SPEC §7.12).
//!
//! The pairing framework ([`crate::pairing`]) authorizes `control.*` mutations. The thin-client
//! model (epic #365) extends the SAME gate to the wallet methods: over the authorized loopback
//! surface, every wallet MUTATION and every custody-lifecycle method requires the master control
//! token OR a valid paired token; an unauthorized caller (no token / a wrong token / a revoked
//! token) is rejected with `-32030 UNAUTHORIZED` before the method runs. Wallet READ methods stay
//! open to local consumers (the read plane, §7.2).
//!
//! # The `auth.*` half is DEPRECATED - frozen for removal (dig_ecosystem#1701)
//!
//! The `auth.*` namespace ([`AUTH_PREFIX`]) gates node-side USER custody, which the #1500
//! ratification (2026-07-22T03:27:48Z) superseded: the node holds no user spend key, and
//! `dig-account`'s `PolicyAuthorizer` is the only enforcing custody gate from here. The gate below
//! is kept EXACTLY as strict for the consumers that already exist - a freeze must not weaken an
//! authorization check on the way out - but no new `auth.*` method may be added, and the namespace
//! is absent from OpenRPC discovery ([`crate::meta`]) so no new consumer can find it.
//!
//! Removal is step 4 of dig_ecosystem#1701 and is deliberately not part of the freeze.
//!
//! Gated wallet methods are ALSO never relayed upstream — a signing/custody request must never
//! leave the loopback node (the server enforces that, [`crate::server`]).
//!
//! This module is PURE (string classification + an allow/deny predicate) so the policy is
//! unit-tested exhaustively without a running server. The gated-mutation set mirrors the dig-wallet
//! Sage mutation surface (SPEC §18.9/§18.9a/§18.16/§18.17); it is kept in sync by SPEC §7.12 — a
//! mutation added to the wallet surface is added here.

use crate::control::{ct_eq, requires_master_token};

/// Sage-parity method names that are ALIASES for a `control.*` capability, paired with the control
/// name that describes the same effect on the same writer.
///
/// The tier of a capability belongs to the capability, NOT to the plane a caller happened to reach
/// it through. `POST /add_peer` and `control.chiaPeers.add` both land on
/// `dig_wallet::sage::network::add_peer`, install the identical `user_managed` row, and grant the
/// identical corroboration-free authority over the wallet replica — so gating one and not the other
/// gates nothing at all. That was the live hole this table closes: the control plane refused a
/// paired token while the parity plane handed it the same writer one URL away.
///
/// The tier itself is NOT restated here. [`master_tier_control_equivalent`] resolves the alias and
/// [`crate::control::requires_master_token`] answers the tier from the published contract, so the
/// two planes cannot drift into disagreeing — there is one rule and two doors onto it.
pub const CONTROL_EQUIVALENT_PARITY_METHODS: &[(&str, &str)] = &[
    ("add_peer", "control.chiaPeers.add"),
    ("remove_peer", "control.chiaPeers.remove"),
];

/// The custody-lifecycle namespace prefix (§18.20/§18.20a): `wallet.create`, `wallet.import`,
/// `wallet.restore`, `wallet.unlock`, `wallet.lock`, `wallet.status`, `wallet.list`,
/// `wallet.select`, `wallet.delete`. EVERY `wallet.*` method is gated by this prefix (even the reads
/// `wallet.status`/`wallet.list`, which reveal which wallets are custodied + their addresses), so a
/// new custody method is gated the moment it lands under `wallet.*` — no per-method allowlist.
pub const CUSTODY_PREFIX: &str = "wallet.";

/// The node-managed unlock-auth namespace prefix (§18.24, #431/#432): `auth.status`, `auth.unlock`,
/// `auth.sign_unlock`, `auth.set_mode`, `auth.set_method`, `auth.enroll_totp`, `auth.enroll_passkey_*`,
/// `auth.lock`, `auth.get_method`. EVERY `auth.*` method is paired-token gated (§7.12) — even the
/// reads reveal the auth posture (mode/method/session state), and `unlock`/`sign_unlock` gate the
/// node-custodied signer — so a new auth method is gated the moment it lands under `auth.*`.
#[deprecated(note = "node-side USER custody is superseded by the #1500 ratification (2026-07-22): dig-account's PolicyAuthorizer is the enforcing custody gate. FROZEN for removal by dig_ecosystem#1701 - no new consumers.")]
pub const AUTH_PREFIX: &str = "auth.";

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
    //
    // `add_peer`/`remove_peer` stay listed here as the FLOOR, not as their tier: they are aliases
    // for master-tier control capabilities ([`CONTROL_EQUIVALENT_PARITY_METHODS`]) and [`classify`]
    // answers `MasterOnly` for them. Should the contract ever demote those capabilities, this
    // membership means they fall back to master-or-paired rather than falling out of the gate
    // entirely — the demotion path fails toward the stricter answer.
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
    /// A custody-lifecycle method (`wallet.*`, §18.20) or a node-managed unlock-auth method
    /// (`auth.*`, §18.24) — GATED.
    Custody,
    /// A wallet MUTATION (sign/spend/offer/mint/transfer + state-changing actions) — GATED to the
    /// master token OR a valid paired token.
    Mutation,
    /// A parity alias for a MASTER-TIER control capability — GATED to the master token ALONE.
    ///
    /// The master tier is every effect that OUTLIVES the token which invoked it, so a paired token
    /// must not reach it on any plane: `pairing.revoke` is the remedy for a compromised paired app,
    /// and an effect that survives revocation has escaped that remedy.
    MasterOnly,
    /// Not a gated wallet method — a wallet READ, a `control.*`/`pairing.*`/`dig.*`/`cache.*`
    /// method, or anything else. This gate leaves it alone (the read plane and the control gate
    /// apply their own policy).
    Other,
}

/// The `control.*` capability a Sage-parity method name is an alias for, when that capability is
/// on the MASTER tier. `None` for every other method — including an alias whose capability the
/// contract puts on the ordinary tier, which then classifies by its wallet-surface membership.
///
/// Reading the tier here rather than hard-coding it is what keeps the two planes in lockstep: the
/// contract is the single rule, and both gates consult it.
pub fn master_tier_control_equivalent(method: &str) -> Option<&'static str> {
    CONTROL_EQUIVALENT_PARITY_METHODS
        .iter()
        .find(|(parity, _)| *parity == method)
        .map(|(_, control)| *control)
        .filter(|control| requires_master_token(control))
}

/// Classify a method against the wallet-authorization policy. PURE.
// Frozen-surface call site (dig_ecosystem#1701): `AUTH_PREFIX` is deprecated to stop NEW
// consumers, and this is the authorization gate the freeze must keep enforcing unchanged. The
// allow sits on the function because an attribute on a tail `if` expression is not stable Rust.
#[allow(deprecated)]
pub fn classify(method: &str) -> WalletMethodClass {
    if method.starts_with(CUSTODY_PREFIX) || method.starts_with(AUTH_PREFIX) {
        WalletMethodClass::Custody
    } else if master_tier_control_equivalent(method).is_some() {
        WalletMethodClass::MasterOnly
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
        WalletMethodClass::Custody | WalletMethodClass::Mutation | WalletMethodClass::MasterOnly
    )
}

/// Decide whether a wallet-surface call is AUTHORIZED. PURE.
///
/// - A method that does NOT require authorization (a read / non-wallet method) is always
///   authorized here — other gates (the read plane, the `control.*` gate) apply their own policy.
/// - A GATED (custody/mutation) method is authorized ONLY when the presented token is the master
///   control token (constant-time) OR a valid paired token (`is_paired`). No token → denied.
/// - A [`WalletMethodClass::MasterOnly`] method — a parity alias for a master-tier control
///   capability — is authorized by the MASTER token alone; a paired token is refused here exactly
///   as `control::requires_master_token` refuses it on the control plane.
///
/// `is_paired` is injected so this stays pure + unit-testable without the on-disk paired-token
/// store; the server passes [`crate::pairing::is_paired_token`].
pub fn authorize(
    method: &str,
    presented: Option<&str>,
    master: &str,
    is_paired: impl Fn(&str) -> bool,
) -> bool {
    let class = classify(method);
    if class == WalletMethodClass::Other {
        return true;
    }
    // Fail CLOSED on an unusable master token (empty in-memory fallback after a CSPRNG
    // mint / persist failure — see `control::is_authorized`). `ct_eq("", "")` is `true`,
    // so without this guard a blank presented token would match a blank master and seize
    // wallet custody/spend. A node with no usable token authorizes NOTHING; a paired
    // token cannot rescue authorization here — the master token gates the paired store.
    if master.is_empty() {
        return false;
    }
    match presented {
        Some(tok) if class == WalletMethodClass::MasterOnly => ct_eq(tok, master),
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
    fn auth_methods_are_gated_and_no_token_is_denied() {
        for m in [
            "auth.status",
            "auth.get_method",
            "auth.set_method",
            "auth.set_mode",
            "auth.enroll_totp",
            "auth.enroll_passkey_begin",
            "auth.enroll_passkey_finish",
            "auth.unlock",
            "auth.sign_unlock",
            "auth.lock",
        ] {
            assert_eq!(classify(m), WalletMethodClass::Custody, "{m}");
            assert!(requires_authorization(m), "{m} must be gated");
            // No token / wrong token → denied; master or paired → allowed.
            assert!(
                !authorize(m, None, MASTER, is_paired),
                "{m}: no token denied"
            );
            assert!(
                !authorize(m, Some("nope"), MASTER, is_paired),
                "{m}: wrong token denied"
            );
            assert!(
                authorize(m, Some(MASTER), MASTER, is_paired),
                "{m}: master ok"
            );
            assert!(
                authorize(m, Some(PAIRED), MASTER, is_paired),
                "{m}: paired ok"
            );
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

    /// Fail-closed regression: an EMPTY master token (the CSPRNG-failure in-memory
    /// sentinel) authorizes NO gated wallet method — not even a blank presented token,
    /// which `ct_eq("", "")` would otherwise accept, seizing custody/spend. A paired
    /// token cannot rescue it either (the master gates the paired store).
    #[test]
    fn empty_master_token_authorizes_no_gated_method() {
        assert!(!authorize("send_xch", Some(""), "", is_paired));
        assert!(!authorize("send_xch", Some("anything"), "", is_paired));
        assert!(!authorize("send_xch", Some(PAIRED), "", is_paired));
        assert!(!authorize("send_xch", None, "", is_paired));
        // Reads stay open regardless (no token needed), and a healthy master still works.
        assert!(authorize("get_coins", None, "", is_paired));
        assert!(authorize("send_xch", Some(MASTER), MASTER, is_paired));
    }

    /// **The master tier is a property of the CAPABILITY, never of the plane it was reached on.**
    ///
    /// This asserts BOTH gates in one test, deliberately. A per-plane test set cannot see the
    /// failure this pins: the control plane refusing a paired token for `control.chiaPeers.add`
    /// and the wallet plane granting that same token `POST /add_peer` are each individually
    /// correct-looking, and both suites stayed green while a paired token installed a
    /// corroboration-free Chia peer that survived `pairing.revoke`. Only an assertion that reads
    /// both policies for the same capability at once can fail on that divergence.
    ///
    /// Divergence output, for the reader who sees this fail: the control-plane assertion names the
    /// contract's answer and the wallet-plane assertion names this module's, so the failing line
    /// says which of the two moved.
    #[test]
    fn the_master_tier_is_a_property_of_the_capability_not_of_the_plane() {
        for (parity, control_name) in CONTROL_EQUIVALENT_PARITY_METHODS {
            // Plane 1 — the control gate, read from the published contract.
            assert!(
                crate::control::requires_master_token(control_name),
                "{control_name} left the master tier: either restore it, or drop {parity} from \
                 CONTROL_EQUIVALENT_PARITY_METHODS deliberately"
            );
            // Plane 2 — the Sage-parity wallet gate, for the SAME capability and the SAME writer.
            assert_eq!(
                classify(parity),
                WalletMethodClass::MasterOnly,
                "{parity} is an alias for master-tier {control_name}, so the wallet plane must \
                 refuse a paired token too -- both land on the same writer"
            );
            assert!(
                !authorize(parity, Some(PAIRED), MASTER, is_paired),
                "a PAIRED token reached {parity}, which is {control_name} by another URL: the \
                 escalation is closed on the control plane and open on the wallet plane"
            );
            assert!(
                authorize(parity, Some(MASTER), MASTER, is_paired),
                "{parity}: the master token must still work"
            );
            assert!(
                !authorize(parity, None, MASTER, is_paired),
                "{parity}: no token is denied"
            );
            assert!(
                !authorize(parity, Some("wrong-token"), MASTER, is_paired),
                "{parity}: a wrong token is denied"
            );
        }
    }

    /// Every master-tier Chia-peer capability the node serves has its parity alias gated with it.
    ///
    /// The table above is a manual mapping, so this is what stops it going stale: a new
    /// `control.chiaPeers.*` capability on the master tier fails here until its Sage-parity name is
    /// mapped, rather than shipping master-gated on one plane and paired-reachable on the other.
    #[test]
    fn every_master_tier_chia_peer_capability_has_a_gated_parity_alias() {
        for control_name in crate::control::CONTROL_METHODS
            .iter()
            .filter(|m| m.starts_with("control.chiaPeers."))
            .filter(|m| crate::control::requires_master_token(m))
        {
            assert!(
                CONTROL_EQUIVALENT_PARITY_METHODS
                    .iter()
                    .any(|(_, mapped)| mapped == control_name),
                "{control_name} is master-tier on the control plane with no parity alias mapped -- \
                 add it to CONTROL_EQUIVALENT_PARITY_METHODS or its wallet-plane twin is open"
            );
        }
    }

    /// The empty-master fail-closed guard covers the master-only class too: with no usable master
    /// token, `ct_eq("", "")` would otherwise hand a blank caller the strictest capability there is.
    #[test]
    fn empty_master_token_authorizes_no_master_only_method() {
        for (parity, _) in CONTROL_EQUIVALENT_PARITY_METHODS {
            assert!(!authorize(parity, Some(""), "", is_paired), "{parity}");
            assert!(!authorize(parity, Some(PAIRED), "", is_paired), "{parity}");
            assert!(!authorize(parity, None, "", is_paired), "{parity}");
        }
    }
}
