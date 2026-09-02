//! Announce the wallet-related environment this process actually resolved (#392).
//!
//! Two independent resolvers decide "the per-user base directory" inside one `dig-node` process,
//! and they can disagree:
//!
//! - [`dig_wallet::autoseed::user_base`] is ENV-FIRST (`LOCALAPPDATA`, then `HOME`, then `"."`), so
//!   it honours an override. It owns `DigWallet/seed.bin`, `wallet.meta.json` and
//!   `DigNode/device/device.key`.
//! - [`dig_node_core::platform_user_base`] asks the OS for the Known Folder and only then falls
//!   back to the environment. It owns `cache/`, `config.json` and therefore `wallet.sqlite`, the
//!   coin replica.
//!
//! Under an override the node came up with a NEWLY MINTED seed under one root and a coin replica
//! under another, and the only thing it said was that it had minted a wallet - which reads as a
//! clean first run rather than as a wallet split in half.
//!
//! # Two causes of a split, and only one of them is anybody's fault
//!
//! The roots can differ WITHOUT anyone overriding anything, and that case is ordinary rather than
//! dangerous. On Linux `directories::BaseDirs` resolves the home directory by reading `$HOME` and
//! then falling back to `getpwuid_r`, while `autoseed::user_base` has no such fallback - so in a
//! unit with no `HOME=` in its environment the node base resolves to the passwd entry (`/root` for
//! a root-run service) while the wallet base collapses to `"."`. The shipped
//! `packaging/linux/systemd/net.dignetwork.dig-node.service` is exactly that shape: no `User=`, no
//! `Group=`, no `HOME=`, its only `Environment=` line being `DIG_NODE_RUN_CONTEXT=service`.
//!
//! Refusing to mint there would leave every stock `.deb` install wallet-less, which is the failure
//! this ticket exists to remove rather than one to introduce. So the two causes are distinguished:
//!
//! | case | verdict |
//! |---|---|
//! | stock Linux `.deb` service (`LOCALAPPDATA` unset, `HOME` unset) | Proceed - no override |
//! | ordinary Windows host / LocalSystem service (env equals the API, modulo case) | Proceed - not a split after normalization |
//! | `LOCALAPPDATA` overridden, no `DIG_NODE_CACHE`, no seed | REFUSE - and the named remedy works |
//! | `LOCALAPPDATA` and `DIG_NODE_CACHE` both set | Proceed, warn only |
//! | container with neither `HOME` nor `LOCALAPPDATA` | Proceed, warn only |
//!
//! Ambiguity resolves toward Proceed. Refusing to mint is the destructive direction here; a warning
//! nobody needed costs a log line.
//!
//! # Why this module announces instead of unifying
//!
//! Making either resolver defer to the other is the obvious fix and it is the destructive one. On a
//! service run [`crate::state::anchor_service_data_dirs`] points `DIG_NODE_CACHE` at the machine
//! state dir, so deriving the wallet base from the node's cache dir would move the seed off
//! `...systemprofile\AppData\Local\DigWallet\seed.bin`, find nothing there, and mint a FRESH wallet
//! on every existing install - orphaning the operator wallet and any $DIG in it. That anchoring is
//! CONDITIONAL, not unconditional: it returns early unless [`crate::state::running_as_service`] is
//! true, which reads `DIG_NODE_RUN_CONTEXT` (`entrypoint.rs`, before the dispatch to serve). The
//! systemd unit bakes that variable in, so on Linux the anchor definitely fires; a Windows service
//! whose registered environment lacks it does NOT anchor, and its cache stays under the
//! systemprofile path. The conclusion is unchanged either way - the seed must not be re-rooted onto
//! the cache - because it only has to hold on the installs where the anchor DOES fire.
//!
//! Resolution therefore stays exactly as it is. What changes is that the split is said out loud,
//! and that the one irreversible consequence - minting a brand new seed into a deliberately split
//! layout - is refused rather than performed quietly.
//!
//! # Shape
//!
//! A pure decision core ([`same_root`], [`split_of`], [`mint_decision`], [`inert_wallet_port`])
//! that takes its inputs as arguments, plus thin env-reading and log-emitting wrappers - the same
//! split [`crate::logging::degrade_announcement`] and [`crate::state::service_data_dir_overrides`]
//! use, and for the same reason: the interesting branch is the one that does NOT occur on the
//! machine the tests run on, so it must be reachable without mutating the process environment.
//! Case-insensitivity is a PARAMETER rather than a `cfg!(windows)` read inside the comparison, so
//! both arms are exercised by the Linux CI runners that are the only ones this repo has.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The env var an operator sets to place the node's cache - and therefore `config.json` and the
/// `wallet.sqlite` replica - deliberately. Setting it is how the refusal below is answered.
pub const CACHE_DIR_ENV: &str = "DIG_NODE_CACHE";

/// The env var whose override moves the wallet half and not the node half.
pub const LOCAL_APP_DATA_ENV: &str = "LOCALAPPDATA";

/// Why the two roots differ. The distinction decides whether anything may be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitCause {
    /// An operator set `LOCALAPPDATA` to something other than the node's own base. They moved one
    /// half deliberately, so telling them to move the other half is advice they can act on.
    Overridden,
    /// The two resolvers landed apart with nobody overriding anything - the `HOME`-unset service
    /// unit, or a container with neither variable. Nothing here is refused: there is no override to
    /// undo, and `DIG_NODE_CACHE` would not address it.
    Ambient,
}

/// The two disagreeing roots, as this process resolved them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRootSplit {
    /// Where the seed, its metadata and the device key live (env-first, honours the override).
    pub wallet_base: PathBuf,
    /// Where the cache, config and the `wallet.sqlite` replica live (OS-first, ignores it).
    pub node_base: PathBuf,
    /// Whether an operator caused this, or the environment did.
    pub cause: SplitCause,
}

/// What start-up should do about a split, given whether a seed already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintDecision {
    /// Run the ordinary bootstrap.
    Proceed,
    /// Do not mint: there is no wallet yet, an override split the two halves, and the operator has
    /// not taken control of the replica location.
    RefuseSplitRoot,
}

/// The prose for an OVERRIDE-caused split. See [`crate::logging::FILE_LOGGING_DEGRADED`] for why
/// these are `concat!` constants and never `\`-continued string literals: a formatter run rejoins a
/// continuation and materialises the source indentation into the string, which no assertion on the
/// surrounding code can see. `the_announcements_have_no_lost_string_continuation` guards it.
pub const SPLIT_ROOTS: &str = concat!(
    "the wallet's per-user root and the node's per-user root DISAGREE in this process. ",
    "LOCALAPPDATA relocated the seed, its metadata and the device key, but NOT the node's ",
    "cache, config.json, or the wallet.sqlite coin replica - those resolve through the OS ",
    "known-folder API, which does not read that variable. The replica this run will open is ",
    "logged as `replica` below; note it sits BESIDE the cache directory, not inside it. To put ",
    "both halves in one place set DIG_NODE_CACHE as well, or unset LOCALAPPDATA to leave both ",
    "at the machine default."
);

/// The prose for an AMBIENT split - the roots differ and nobody overrode anything.
///
/// It must NOT name `DIG_NODE_CACHE` as the remedy, because setting it does not change where the
/// seed resolves and the predicate does not consult it on this path. Nothing is refused here; this
/// is purely the honest version of the silence this ticket is about.
pub const AMBIENT_SPLIT_ROOTS: &str = concat!(
    "the wallet's per-user root and the node's per-user root resolved to DIFFERENT places, and ",
    "no override caused it: neither LOCALAPPDATA nor HOME is set in this environment, so the ",
    "wallet's env-first resolver fell back to the working directory while the node's asked the ",
    "OS for the account's home. Both resolved roots are logged below as `wallet_base` and ",
    "`node_base`, and the seed file this run will read or create is logged as `seed`. Nothing ",
    "is refused and nothing is wrong with the wallet; set HOME in the service environment if you ",
    "want the two halves to share one root."
);

/// The prose for the refusal.
///
/// It must leave no doubt that the disk was not touched: an operator who reads a mint failure as a
/// partial write goes looking for something to delete, and deleting is the one act this refusal
/// exists to prevent. Every escape it names is one [`mint_decision`] actually honours - setting
/// `DIG_NODE_CACHE` flips the verdict to `Proceed`, and so does unsetting `LOCALAPPDATA`, because
/// that removes the override the refusal is conditioned on.
pub const REFUSED_SPLIT_MINT: &str = concat!(
    "no wallet exists yet and an overridden LOCALAPPDATA has split the wallet root away from the ",
    "node root, so NOTHING was minted and NOTHING was written. Minting here would put the seed ",
    "under one root and the wallet.sqlite replica under another. Set DIG_NODE_CACHE as well as ",
    "LOCALAPPDATA so both halves land in one place, or unset LOCALAPPDATA, then start the node ",
    "again."
);

/// The prose for an inert `DIG_WALLET_PORT`. A variable that is read by nobody is worse than an
/// unsupported one, because it looks configured.
pub const INERT_WALLET_PORT: &str = concat!(
    "DIG_WALLET_PORT is set, but dig-node serves NO wallet UI and nothing will listen on that ",
    "port. The variable is honoured only by the DIG Browser runtime and by the standalone ",
    "dig-wallet binary."
);

/// Whether two paths name the same root, ignoring trailing separators and - when asked - case.
///
/// `case_insensitive` is a PARAMETER, never a `cfg!(windows)` read in the body: CI runs on
/// `ubuntu-latest` only, so an internal `cfg!` would leave the Windows arm of this comparison
/// untested on every runner this repo has. Exact `PathBuf` equality here would report a FALSE split
/// on an ordinary Windows host whose `LOCALAPPDATA` differs from the Known Folder result by case or
/// by a trailing backslash - and on a fresh install that is a permanent refusal to mint.
///
/// Deliberately does NOT canonicalize: [`std::fs::canonicalize`] requires the paths to exist and
/// returns `\\?\`-prefixed results on Windows, so it would introduce two new ways to disagree.
pub fn same_root(a: &Path, b: &Path, case_insensitive: bool) -> bool {
    let (a, b) = (trim_trailing_separators(a), trim_trailing_separators(b));
    if case_insensitive {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// A path as a string with any trailing separators removed, keeping a bare root as-is.
fn trim_trailing_separators(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        raw.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Whether the two roots disagree, and why. `Some` iff they are genuinely different roots. Pure.
///
/// `local_app_data` is the raw `LOCALAPPDATA` of the environment being described - `None` when it
/// is unset. A split is [`SplitCause::Overridden`] only when that variable is set AND points
/// somewhere other than the node's own base: Windows sets the two identically, so an ordinary
/// Windows host is not an override, and Linux normally leaves the variable unset entirely.
pub fn split_of(
    wallet_base: &Path,
    node_base: &Path,
    local_app_data: Option<&Path>,
    case_insensitive: bool,
) -> Option<WalletRootSplit> {
    if same_root(wallet_base, node_base, case_insensitive) {
        return None;
    }
    let overridden =
        local_app_data.is_some_and(|value| !same_root(value, node_base, case_insensitive));
    Some(WalletRootSplit {
        wallet_base: wallet_base.to_path_buf(),
        node_base: node_base.to_path_buf(),
        cause: if overridden {
            SplitCause::Overridden
        } else {
            SplitCause::Ambient
        },
    })
}

/// [`split_of`] against the two resolvers this process actually uses.
///
/// The one place the pure core is bound to the real functions - and therefore the one place a
/// wrong pair of functions would hide, which is why it has its own environment-level test.
pub fn wallet_root_split() -> Option<WalletRootSplit> {
    let local_app_data = std::env::var_os(LOCAL_APP_DATA_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    split_of(
        &dig_wallet::autoseed::user_base(),
        &dig_node_core::platform_user_base(),
        local_app_data.as_deref(),
        cfg!(windows),
    )
}

/// Whether the operator has taken control of the replica location with `DIG_NODE_CACHE`. An empty
/// value is unset, matching how [`crate::state`] parses its own overrides.
pub fn cache_override_set() -> bool {
    std::env::var(CACHE_DIR_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Whether start-up may mint. Pure.
///
/// Refuses on the conjunction of three things and nothing less: an OVERRIDE-caused split, no seed
/// on disk, and no `DIG_NODE_CACHE`. Every other combination proceeds.
///
/// - A split with a seed ALREADY on disk proceeds: that host is running, its two halves are
///   whatever they are, and refusing would break a working install to enforce a layout rule.
/// - An AMBIENT split proceeds, because there is no override to undo and the refusal's own remedy
///   would not address it. This is the stock Linux `.deb` service, and refusing there would leave
///   every such install wallet-less.
/// - A split with `DIG_NODE_CACHE` set proceeds, because the operator has placed the replica
///   deliberately - that is precisely the remedy the refusal names, so honouring it is what makes
///   that sentence true.
pub fn mint_decision(
    split: Option<&WalletRootSplit>,
    seed_present: bool,
    cache_override: bool,
) -> MintDecision {
    match (split.map(|s| s.cause), seed_present, cache_override) {
        (Some(SplitCause::Overridden), false, false) => MintDecision::RefuseSplitRoot,
        _ => MintDecision::Proceed,
    }
}

/// The port an operator set that nothing in this binary will bind. Pure; empty is unset.
pub fn inert_wallet_port(raw: Option<&str>) -> Option<&str> {
    raw.filter(|p| !p.is_empty())
}

/// The coin replica that hangs off the node's config, given that config's path.
///
/// A SIBLING of the config file, which is itself a sibling of the cache directory - so an operator
/// who sets `DIG_NODE_CACHE` and then looks for `wallet.sqlite` INSIDE that directory does not find
/// it, and concludes the second lever failed too. Naming the resolved file is worth more than
/// naming the variable. Pure, so the derivation is checkable without resolving anything.
pub fn replica_beside(config: &Path) -> PathBuf {
    config
        .parent()
        .map(|p| p.join("wallet.sqlite"))
        .unwrap_or_else(|| PathBuf::from("wallet.sqlite"))
}

/// [`replica_beside`] against the config path this process resolves.
pub fn replica_path() -> PathBuf {
    replica_beside(&dig_node_core::config_path())
}

/// Emitted once per process; a serve entrypoint that runs twice must not say it twice.
static ANNOUNCED: AtomicBool = AtomicBool::new(false);

/// Warn about every wallet-environment condition this run resolved into.
///
/// Called from the serve entrypoints BEFORE the bootstrap, so an operator reads why a wallet was
/// refused before - not after - the line that would have said one was minted.
pub fn announce(
    split: Option<&WalletRootSplit>,
    replica: &Path,
    seed: &Path,
    wallet_port: Option<&str>,
) {
    if ANNOUNCED.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(split) = split {
        match split.cause {
            SplitCause::Overridden => tracing::warn!(
                wallet_base = %split.wallet_base.display(),
                node_base = %split.node_base.display(),
                replica = %replica.display(),
                "{SPLIT_ROOTS}"
            ),
            SplitCause::Ambient => tracing::warn!(
                wallet_base = %split.wallet_base.display(),
                node_base = %split.node_base.display(),
                seed = %seed.display(),
                "{AMBIENT_SPLIT_ROOTS}"
            ),
        }
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
    announce(
        split.as_ref(),
        &replica_path(),
        &dig_wallet::autoseed::default_paths().seed,
        inert_wallet_port(raw.as_deref()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes every test that mutates `LOCALAPPDATA` (the `ENV_LOCK` idiom `dig-wallet`'s own
    /// tests use): the lib tests share one process, so an unguarded override leaks into any
    /// concurrent test resolving a per-user path.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// An override-shaped split: the operator moved the wallet half somewhere of their own.
    fn overridden() -> WalletRootSplit {
        split_of(
            Path::new("/scratch"),
            Path::new("/node"),
            Some(Path::new("/scratch")),
            false,
        )
        .expect("an override splits the roots")
    }

    /// The stock Linux `.deb` shape: no `LOCALAPPDATA`, no `HOME`, so the wallet half collapses to
    /// "." while the node half falls through `getpwuid_r` to the account home.
    fn ambient() -> WalletRootSplit {
        split_of(Path::new("."), Path::new("/root"), None, false)
            .expect("divergent roots are still a split")
    }

    #[test]
    fn equal_roots_are_not_a_split() {
        assert_eq!(
            split_of(Path::new("/a"), Path::new("/a"), None, false),
            None
        );
    }

    #[test]
    fn differing_roots_are_a_split_naming_both() {
        let split = split_of(Path::new("/wallet"), Path::new("/node"), None, false).expect("split");
        assert_eq!(split.wallet_base, PathBuf::from("/wallet"));
        assert_eq!(split.node_base, PathBuf::from("/node"));
    }

    /// Both arms of the case parameter, so the Windows behaviour is exercised on a Linux runner.
    /// Trailing separators never matter; genuine difference always does.
    #[test]
    fn same_root_normalizes_trailing_separators_and_optionally_case() {
        assert!(same_root(Path::new("/a/b"), Path::new("/a/b"), false));
        assert!(same_root(Path::new("/a/b"), Path::new("/a/b"), true));

        assert!(!same_root(
            Path::new("C:\\Users\\Micha"),
            Path::new("C:\\Users\\micha"),
            false
        ));
        assert!(same_root(
            Path::new("C:\\Users\\Micha"),
            Path::new("C:\\Users\\micha"),
            true
        ));

        assert!(same_root(Path::new("/a/b/"), Path::new("/a/b"), false));
        assert!(same_root(
            Path::new("C:\\Users\\micha\\"),
            Path::new("C:\\Users\\micha"),
            true
        ));

        assert!(!same_root(Path::new("/a/b"), Path::new("/a/c"), false));
        assert!(!same_root(Path::new("/a/b"), Path::new("/a/c"), true));
    }

    /// An ordinary Windows host has `LOCALAPPDATA` equal to the Known Folder result modulo case, so
    /// there must be no split at all - not merely no refusal. Exact equality reported one, and on a
    /// fresh install that was a permanent refusal to mint.
    #[test]
    fn a_case_differing_windows_root_is_not_a_split() {
        let env = Path::new("C:\\Users\\Micha\\AppData\\Local");
        let api = Path::new("C:\\Users\\micha\\AppData\\Local\\");
        assert_eq!(split_of(env, api, Some(env), true), None);
    }

    /// A split with nobody overriding anything is AMBIENT, and one with an override is not.
    #[test]
    fn the_cause_tracks_whether_localappdata_actually_overrode_anything() {
        assert_eq!(ambient().cause, SplitCause::Ambient);
        assert_eq!(overridden().cause, SplitCause::Overridden);
        // Set, but to the node's own base: nobody moved anything.
        let split = split_of(
            Path::new("."),
            Path::new("/node"),
            Some(Path::new("/node")),
            false,
        )
        .expect("still a split");
        assert_eq!(split.cause, SplitCause::Ambient);
    }

    /// **Proves:** the stock Linux `.deb` service mints. The shipped unit carries no `User=`, no
    /// `HOME=` and no `LOCALAPPDATA`, so the roots diverge with nobody at fault; refusing there
    /// would leave every such install wallet-less, which is the #1928 shape this ticket removes.
    #[test]
    fn a_stock_linux_service_shaped_split_proceeds() {
        assert_eq!(
            mint_decision(Some(&ambient()), false, false),
            MintDecision::Proceed
        );
    }

    /// **Proves:** the remedy the refusal NAMES is one the predicate HONOURS.
    ///
    /// Bound to `mint_decision` rather than to the text: a test that only grepped
    /// `REFUSED_SPLIT_MINT` for "DIG_NODE_CACHE" passed against the version where setting it
    /// changed nothing, which is exactly the lying-error-message defect this round fixes.
    #[test]
    fn setting_the_named_cache_override_lifts_the_refusal() {
        let split = overridden();
        assert_eq!(
            mint_decision(Some(&split), false, false),
            MintDecision::RefuseSplitRoot,
            "the measured defect must still be caught"
        );
        assert_eq!(
            mint_decision(Some(&split), false, true),
            MintDecision::Proceed,
            "DIG_NODE_CACHE is named as the escape, so it must actually be one"
        );
        assert!(REFUSED_SPLIT_MINT.contains(CACHE_DIR_ENV));
    }

    /// Every arm of the three-input table. A table missing an arm leaves the interesting one
    /// untested, and the interesting ones are all the arms that must NOT refuse.
    #[test]
    fn mint_is_refused_only_for_an_unanswered_override_with_no_wallet() {
        for (split, seed, cache, want) in [
            (
                Some(overridden()),
                false,
                false,
                MintDecision::RefuseSplitRoot,
            ),
            (Some(overridden()), true, false, MintDecision::Proceed),
            (Some(overridden()), false, true, MintDecision::Proceed),
            (Some(overridden()), true, true, MintDecision::Proceed),
            (Some(ambient()), false, false, MintDecision::Proceed),
            (Some(ambient()), true, false, MintDecision::Proceed),
            (None, false, false, MintDecision::Proceed),
            (None, true, false, MintDecision::Proceed),
        ] {
            assert_eq!(
                mint_decision(split.as_ref(), seed, cache),
                want,
                "split={split:?} seed={seed} cache={cache}"
            );
        }
    }

    #[test]
    fn an_empty_wallet_port_is_unset() {
        assert_eq!(inert_wallet_port(Some("9877")), Some("9877"));
        assert_eq!(inert_wallet_port(None), None);
        assert_eq!(inert_wallet_port(Some("")), None);
    }

    /// The replica is a SIBLING of the config file, never a child of the cache directory.
    #[test]
    fn the_replica_sits_beside_the_config_not_inside_the_cache() {
        assert_eq!(
            replica_beside(Path::new("/iso/config.json")),
            PathBuf::from("/iso/wallet.sqlite")
        );
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

    /// The ambient sentence must NOT prescribe the override remedy, because the predicate does not
    /// consult `DIG_NODE_CACHE` on that path and setting it would change nothing an operator sees.
    /// An error message naming an inert escape is the defect this ticket fixes, one layer up.
    #[test]
    fn the_ambient_announcement_does_not_prescribe_an_inert_remedy() {
        assert!(
            !AMBIENT_SPLIT_ROOTS.contains(CACHE_DIR_ENV),
            "DIG_NODE_CACHE does not address an ambient split"
        );
        assert!(AMBIENT_SPLIT_ROOTS.contains("HOME"));
        assert!(AMBIENT_SPLIT_ROOTS.contains("LOCALAPPDATA"));
        assert!(AMBIENT_SPLIT_ROOTS.contains("seed"));
        assert!(AMBIENT_SPLIT_ROOTS.contains("Nothing is refused"));
    }

    /// The one test that reproduces the REPORTED condition rather than a property of the pure
    /// core: with `LOCALAPPDATA` overridden, the wrapper must report an OVERRIDE-caused split
    /// naming it. Without it the pure tests would all pass over a wrapper wired to the wrong pair
    /// of functions - which is precisely the defect, one layer up.
    ///
    /// Serialized on a module-local lock and restores the variable, because `cargo test` runs the
    /// lib tests in one process and a mid-flight `LOCALAPPDATA` would be read by anything else
    /// resolving a per-user path. Nothing here writes to disk: it compares two resolved paths.
    #[test]
    fn an_overridden_localappdata_is_reported_as_a_split() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var(LOCAL_APP_DATA_ENV).ok();
        let td = tempfile::tempdir().expect("tempdir");

        std::env::set_var(LOCAL_APP_DATA_ENV, td.path());
        let split = wallet_root_split();
        let restored = {
            match &restore {
                Some(v) => std::env::set_var(LOCAL_APP_DATA_ENV, v),
                None => std::env::remove_var(LOCAL_APP_DATA_ENV),
            }
            wallet_root_split()
        };

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
            split.cause,
            SplitCause::Overridden,
            "an override is not an ambient divergence"
        );
        assert_eq!(
            mint_decision(Some(&split), false, false),
            MintDecision::RefuseSplitRoot,
            "the reported condition is the one that refuses"
        );
        assert_eq!(restored, None, "restoring the variable removes the split");
    }

    /// A `\`-continued literal carries its source indentation into the string. Assert on the
    /// rendered text, because that is the only artifact a formatter cannot rewrite behind us.
    #[test]
    fn the_announcements_have_no_lost_string_continuation() {
        for text in [
            SPLIT_ROOTS,
            AMBIENT_SPLIT_ROOTS,
            REFUSED_SPLIT_MINT,
            INERT_WALLET_PORT,
        ] {
            assert!(!text.contains("    "), "run of 4+ spaces in: {text}");
        }
    }
}
