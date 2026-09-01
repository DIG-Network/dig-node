//! Announce the wallet-related environment this process actually resolved (#392).
//!
//! Two independent resolvers decide "the per-user base directory" inside one `dig-node` process,
//! and they disagree the moment an operator overrides `LOCALAPPDATA`:
//!
//! - [`dig_wallet::autoseed::user_base`] is ENV-FIRST, so it honours the override. It owns
//!   `DigWallet/seed.bin`, `wallet.meta.json` and `DigNode/device/device.key`.
//! - [`dig_node_core::platform_user_base`] asks the OS for the Known Folder and only falls back to
//!   the environment, so on Windows it ignores the override. It owns `cache/`, `config.json` and
//!   therefore `wallet.sqlite`, the coin replica.
//!
//! Under an override the node came up with a NEWLY MINTED seed under one root and a coin replica
//! under another, and the only thing it said was that it had minted a wallet - which reads as a
//! clean first run rather than as a wallet split in half.
//!
//! # Why this module announces instead of unifying
//!
//! Making either resolver defer to the other is the obvious fix and it is the destructive one. On a
//! service run [`crate::state::anchor_service_data_dirs`] points `DIG_NODE_CACHE` at
//! `C:\ProgramData\DigNode\cache`, so deriving the wallet base from the node's cache dir would move
//! the seed off `...systemprofile\AppData\Local\DigWallet\seed.bin`, find nothing there, and mint a
//! FRESH wallet on every existing install - orphaning the operator wallet and any $DIG in it.
//! Resolution therefore stays exactly as it is. What changes is that the split is said out loud,
//! and that the one irreversible consequence - minting a brand new seed into a split layout - is
//! refused rather than performed quietly.
//!
//! # Shape
//!
//! A pure decision core ([`split_of`], [`mint_decision`], [`inert_wallet_port`]) that takes its
//! inputs as arguments, plus thin env-reading and log-emitting wrappers - the same split
//! [`crate::logging::degrade_announcement`] and [`crate::state::service_data_dir_overrides`] use,
//! and for the same reason: the interesting branch is the one that does NOT occur on the machine
//! the tests run on, so it must be reachable without mutating the process environment.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The two disagreeing roots, as this process resolved them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRootSplit {
    /// Where the seed, its metadata and the device key live (env-first, honours the override).
    pub wallet_base: PathBuf,
    /// Where the cache, config and the `wallet.sqlite` replica live (OS-first, ignores it).
    pub node_base: PathBuf,
}

/// What start-up should do about a split, given whether a seed already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintDecision {
    /// Run the ordinary bootstrap.
    Proceed,
    /// Do not mint: there is no wallet yet and minting one now would write it into a layout whose
    /// two halves are already known to disagree.
    RefuseSplitRoot,
}

/// The prose for the split warning. See [`crate::logging::FILE_LOGGING_DEGRADED`] for why these are
/// `concat!` constants and never `\`-continued string literals: a formatter run rejoins a
/// continuation and materialises the source indentation into the string, which no assertion on the
/// surrounding code can see. `the_announcements_have_no_lost_string_continuation` guards it.
pub const SPLIT_ROOTS: &str = concat!(
    "the wallet's per-user root and the node's per-user root DISAGREE in this process. ",
    "LOCALAPPDATA relocated the seed, its metadata and the device key, but NOT the node's ",
    "cache, config.json, or the wallet.sqlite coin replica - those resolve through the OS ",
    "known-folder API, which does not read that variable. Set DIG_NODE_CACHE to move the ",
    "replica and cache alongside the seed, or unset LOCALAPPDATA to leave both at the ",
    "machine default."
);

/// The prose for the refusal. It must leave no doubt that the disk was not touched: an operator who
/// reads a mint failure as a partial write goes looking for something to delete, and deleting is
/// the one act this refusal exists to prevent.
pub const REFUSED_SPLIT_MINT: &str = concat!(
    "no wallet exists yet and the wallet and node roots disagree, so NOTHING was minted and ",
    "NOTHING was written. Minting here would put the seed under one root and the wallet.sqlite ",
    "replica under another. Set DIG_NODE_CACHE alongside LOCALAPPDATA so both halves land in ",
    "one place, or unset LOCALAPPDATA, then start the node again."
);

/// The prose for an inert `DIG_WALLET_PORT`. A variable that is read by nobody is worse than an
/// unsupported one, because it looks configured.
pub const INERT_WALLET_PORT: &str = concat!(
    "DIG_WALLET_PORT is set, but dig-node serves NO wallet UI and nothing will listen on that ",
    "port. The variable is honoured only by the DIG Browser runtime and by the standalone ",
    "dig-wallet binary."
);

/// Whether the two roots disagree. `Some` iff they differ. Pure.
pub fn split_of(wallet_base: &Path, node_base: &Path) -> Option<WalletRootSplit> {
    if wallet_base == node_base {
        return None;
    }
    Some(WalletRootSplit {
        wallet_base: wallet_base.to_path_buf(),
        node_base: node_base.to_path_buf(),
    })
}

/// [`split_of`] against the two resolvers this process actually uses.
///
/// The one place the pure core is bound to the real functions - and therefore the one place a
/// wrong pair of functions would hide, which is why it has its own environment-level test.
pub fn wallet_root_split() -> Option<WalletRootSplit> {
    split_of(
        &dig_wallet::autoseed::user_base(),
        &dig_node_core::platform_user_base(),
    )
}

/// Whether start-up may mint. Pure.
///
/// A split with a seed ALREADY on disk proceeds: that host is running, its two halves are whatever
/// they are, and refusing would break a working install to enforce a layout rule. The refusal is
/// reserved for the irreversible case - creating a new wallet into a layout already known to be
/// split.
pub fn mint_decision(split: Option<&WalletRootSplit>, seed_present: bool) -> MintDecision {
    match (split, seed_present) {
        (Some(_), false) => MintDecision::RefuseSplitRoot,
        _ => MintDecision::Proceed,
    }
}

/// The port an operator set that nothing in this binary will bind. Pure; empty is unset.
pub fn inert_wallet_port(raw: Option<&str>) -> Option<&str> {
    raw.filter(|p| !p.is_empty())
}

/// Emitted once per process; a serve entrypoint that runs twice must not say it twice.
static ANNOUNCED: AtomicBool = AtomicBool::new(false);

/// Warn about every wallet-environment condition this run resolved into.
///
/// Called from the serve entrypoints BEFORE the bootstrap, so an operator reads why a wallet was
/// refused before - not after - the line that would have said one was minted.
pub fn announce(split: Option<&WalletRootSplit>, wallet_port: Option<&str>) {
    if ANNOUNCED.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(split) = split {
        tracing::warn!(
            wallet_base = %split.wallet_base.display(),
            node_base = %split.node_base.display(),
            "{SPLIT_ROOTS}"
        );
    }
    if let Some(port) = wallet_port {
        tracing::warn!(port = %port, "{INERT_WALLET_PORT}");
    }
}

/// The environment reader for [`announce`], kept beside it so a caller passes no arguments and
/// cannot accidentally announce a condition it computed some other way.
pub fn announce_from_env() {
    let split = wallet_root_split();
    let raw = std::env::var("DIG_WALLET_PORT").ok();
    announce(split.as_ref(), inert_wallet_port(raw.as_deref()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes every test that mutates `LOCALAPPDATA` (the `ENV_LOCK` idiom `dig-wallet`'s own
    /// tests use): the lib tests share one process, so an unguarded override leaks into any
    /// concurrent test resolving a per-user path.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn equal_roots_are_not_a_split() {
        assert_eq!(split_of(Path::new("/a"), Path::new("/a")), None);
    }

    #[test]
    fn differing_roots_are_a_split_naming_both() {
        let split = split_of(Path::new("/wallet"), Path::new("/node")).expect("a split");
        assert_eq!(split.wallet_base, PathBuf::from("/wallet"));
        assert_eq!(split.node_base, PathBuf::from("/node"));
    }

    /// All four arms. A table with three rows leaves the interesting one untested, and the
    /// interesting one is (split, seed present) - the arm that must NOT refuse.
    #[test]
    fn mint_is_refused_only_when_a_split_would_create_a_new_wallet() {
        let split = split_of(Path::new("/wallet"), Path::new("/node")).unwrap();
        assert_eq!(
            mint_decision(Some(&split), false),
            MintDecision::RefuseSplitRoot
        );
        assert_eq!(mint_decision(Some(&split), true), MintDecision::Proceed);
        assert_eq!(mint_decision(None, false), MintDecision::Proceed);
        assert_eq!(mint_decision(None, true), MintDecision::Proceed);
    }

    #[test]
    fn an_empty_wallet_port_is_unset() {
        assert_eq!(inert_wallet_port(Some("9877")), Some("9877"));
        assert_eq!(inert_wallet_port(None), None);
        assert_eq!(inert_wallet_port(Some("")), None);
    }

    #[test]
    fn the_announcements_name_what_an_operator_must_change() {
        assert!(SPLIT_ROOTS.contains("LOCALAPPDATA"));
        assert!(SPLIT_ROOTS.contains("DIG_NODE_CACHE"));
        assert!(SPLIT_ROOTS.contains("wallet.sqlite"));
        assert!(REFUSED_SPLIT_MINT.contains("DIG_NODE_CACHE"));
        assert!(REFUSED_SPLIT_MINT.contains("LOCALAPPDATA"));
        assert!(REFUSED_SPLIT_MINT.contains("NOTHING was written"));
        assert!(INERT_WALLET_PORT.contains("DIG_WALLET_PORT"));
        assert!(INERT_WALLET_PORT.contains("dig-wallet"));
    }

    /// The one test that reproduces the REPORTED condition rather than a property of the pure
    /// core: with `LOCALAPPDATA` overridden, the wrapper must report a split naming that override.
    /// Without it the pure tests would all pass over a wrapper wired to the wrong pair of
    /// functions - which is precisely the defect, one layer up.
    ///
    /// Serialized on a module-local lock and restores the variable, because `cargo test` runs the
    /// lib tests in one process and a mid-flight `LOCALAPPDATA` would be read by anything else
    /// resolving a per-user path. Nothing here writes to disk: it compares two resolved paths.
    #[test]
    fn an_overridden_localappdata_is_reported_as_a_split() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var("LOCALAPPDATA").ok();
        let td = tempfile::tempdir().expect("tempdir");

        std::env::set_var("LOCALAPPDATA", td.path());
        let split = wallet_root_split();

        match restore {
            Some(v) => std::env::set_var("LOCALAPPDATA", v),
            None => std::env::remove_var("LOCALAPPDATA"),
        }

        let split = split.expect("an overridden LOCALAPPDATA splits the two roots");
        assert_eq!(
            split.wallet_base,
            td.path(),
            "the wallet root follows the override"
        );
        assert_ne!(
            split.node_base,
            td.path(),
            "the node root does not follow it"
        );
        assert_eq!(
            wallet_root_split(),
            None,
            "restoring the variable removes the split"
        );
    }

    /// A `\`-continued literal carries its source indentation into the string. Assert on the
    /// rendered text, because that is the only artifact a formatter cannot rewrite behind us.
    #[test]
    fn the_announcements_have_no_lost_string_continuation() {
        for text in [SPLIT_ROOTS, REFUSED_SPLIT_MINT, INERT_WALLET_PORT] {
            assert!(!text.contains("    "), "run of 4+ spaces in: {text}");
        }
    }
}
