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

use dig_wallet::autoseed::{self, BootstrapState};

/// Ensure a wallet seed exists, logging the outcome.
///
/// Returns the state so a caller can surface it; callers must not treat any outcome as fatal.
pub fn ensure_wallet_seed() -> Option<BootstrapState> {
    let paths = autoseed::default_paths();

    match autoseed::ensure_wallet(&paths) {
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
            tracing::error!(
                device_key = %paths.device_key.display(),
                "a wallet seed exists but its device key is missing — the wallet cannot be opened \
                 until the key is restored. Nothing was created or modified."
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
