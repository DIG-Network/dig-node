//! Start-up wallet bootstrap — make sure a seed exists before the node serves anything (#277).
//!
//! The node must be usable the moment it is installed, so this runs on EVERY start: first install,
//! after an update, and on every ordinary boot. There is no user in this path and no prompt; if a
//! seed is missing one is minted, and if anything at all is uncertain nothing is written.
//!
//! The whole decision lives in [`dig_wallet::autoseed`]. This module exists only to run it at the
//! right moment and to say — in the operator log, and never with any key material in it — what
//! happened.
//!
//! # Never fatal, and never a fallback either
//!
//! A failure here does NOT stop the node. Serving and reading content have never required a wallet,
//! and refusing to boot a content node because a key file was unreadable would turn a wallet
//! problem into an availability problem. The node comes up **wallet-less and says so**.
//!
//! What it must never do is degrade: there is no plaintext path, no prompt, and no "try again
//! without the device key". A fallback would quietly become the real design on exactly the
//! constrained hosts this is meant to serve.

use dig_node_core::shared::at_rest::{presence, Presence};
use dig_wallet::autoseed::{self, BootstrapState, WalletPaths};

use crate::wallet_env::{self, MintDecision};

/// Ensure a wallet seed exists at the node's real per-user location, logging the outcome.
///
/// Returns the state so a caller can surface it; callers must not treat any outcome as fatal.
///
/// Minting is REFUSED when the wallet's per-user root and the node's disagree and there is no seed
/// yet (dig-node#392): the new seed would land under one root while the `wallet.sqlite` coin
/// replica opens under the other, and the operator would be told only that a wallet was minted. A
/// host that ALREADY has a seed proceeds unchanged - it is running, and refusing would break a
/// working install to enforce a layout rule.
pub fn ensure_wallet_seed() -> Option<BootstrapState> {
    ensure_wallet_seed_unless_split(&autoseed::default_paths(), wallet_env::wallet_root_split())
}

/// [`ensure_wallet_seed`] against an explicit layout and an explicit split verdict.
///
/// The split is a PARAMETER for the same reason `ensure_wallet_seed_at` takes its paths: proving
/// that the refusal writes nothing means running it with a split present and no seed on disk, and a
/// test that produced that state by setting the real `LOCALAPPDATA` would be exercising the
/// developer's own wallet directory to assert a property about a refusal.
pub fn ensure_wallet_seed_unless_split(
    paths: &WalletPaths,
    split: Option<wallet_env::WalletRootSplit>,
) -> Option<BootstrapState> {
    if let MintDecision::RefuseSplitRoot =
        wallet_env::mint_decision(split.as_ref(), seed_present(paths))
    {
        tracing::error!("{}", wallet_env::REFUSED_SPLIT_MINT);
        return None;
    }
    ensure_wallet_seed_at(paths)
}

/// Whether a seed is on disk, taking "the question could not be answered" as PRESENT.
///
/// An unreadable seed file - a locked file, an AV scanner, an ACL an OS update changed - must never
/// read as "there is no wallet here", because the only thing that follows from "no wallet" is
/// minting one. [`dig_wallet::autoseed`]'s own `wallet_exists` takes the same unknown-means-present
/// direction, and it is the direction that cannot lose a wallet.
fn seed_present(paths: &WalletPaths) -> bool {
    !matches!(presence(&paths.seed), Ok(Presence::Absent))
}

/// [`ensure_wallet_seed`] against an explicit layout.
///
/// Split out so the narration below — the one place in this feature where a log line sits next to
/// live key material — can be exercised against a temporary directory. A test that had to point the
/// real resolver at the real `%LOCALAPPDATA%` would be minting seeds into the developer's own
/// wallet directory to assert a property about logging.
pub fn ensure_wallet_seed_at(paths: &WalletPaths) -> Option<BootstrapState> {
    match autoseed::ensure_wallet(paths) {
        Ok(BootstrapState::Created) => {
            // Deliberately records only that a wallet now exists. The phrase, the seed and the
            // device key never reach a log field — the node's logs are operator-readable and are
            // collected into support bundles (SPEC §7, the `never_log` battery).
            tracing::info!(
                origin = "auto",
                "no wallet was present; minted one and sealed it under this machine's device key"
            );
            Some(BootstrapState::Created)
        }
        Ok(BootstrapState::Opened) => {
            tracing::debug!("wallet seed present and readable");
            Some(BootstrapState::Opened)
        }
        Ok(BootstrapState::Locked) => {
            // The ordinary state for an imported wallet: sealed under the user's password, which
            // this path does not have and must not want.
            tracing::debug!("wallet seed present; it opens with the owner's password, not here");
            Some(BootstrapState::Locked)
        }
        Ok(BootstrapState::Orphaned) => {
            // Loud, because it is recoverable ONLY while nothing overwrites it — a wrong mount, a
            // half-restored backup, a container started without its volume. Restoring the device
            // key restores the wallet; minting a new one would destroy it silently, so nothing was
            // minted.
            //
            // This arm is reached ONLY for a wallet marked `auto` — one this node minted, which
            // therefore genuinely should have a key. An imported wallet with no device key is the
            // ordinary case and takes the quiet `Locked` arm above. That distinction matters more
            // than it looks: told that their wallet "cannot be opened", a reasonable person goes
            // looking for a way to start over, and starting over is exactly the destructive act
            // this refusal exists to prevent. The sentence must therefore be reserved for the
            // situation that is actually wrong, and must say what to do instead of implying loss.
            tracing::error!(
                device_key = %paths.device_key.display(),
                "this node's auto-created wallet is present but its device key is missing. The \
                 wallet is INTACT and recoverable: restore the device key file and it opens again. \
                 Nothing was created, modified or deleted — do not delete the wallet."
            );
            Some(BootstrapState::Orphaned)
        }
        Err(e) => {
            tracing::error!(
                error = ?e,
                "could not establish a wallet; the node is running without one. Nothing was written."
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The refusal must leave the disk exactly as it found it. Asserted on the seed file itself,
    /// not on the returned state: a decision that returned `None` while still minting would satisfy
    /// any assertion about the return value alone.
    #[test]
    fn a_split_root_with_no_seed_mints_nothing() {
        let td = tempfile::tempdir().expect("tempdir");
        let paths = WalletPaths {
            seed: td.path().join("DigWallet").join("seed.bin"),
            device_key: td.path().join("DigNode").join("device").join("device.key"),
            meta: td.path().join("DigWallet").join("wallet.meta.json"),
        };
        let split = wallet_env::split_of(Path::new("/wallet-root"), Path::new("/node-root"));
        assert!(split.is_some(), "the fixture must actually be split");

        let state = ensure_wallet_seed_unless_split(&paths, split);

        assert!(state.is_none(), "a refused mint reports no wallet state");
        assert!(!paths.seed.exists(), "the seed file was NOT created");
        assert!(!paths.meta.exists(), "no metadata was written either");
        assert!(!paths.device_key.exists(), "no device key was written");
    }
}
