//! The rescue path for a seed the node used to custody, exercised through the real CLI.
//!
//! dig_ecosystem#1701 removed every node-side USER custody surface, including the embedded
//! wallet's `/api/export`. That is only safe because a seed already on disk stays
//! recoverable — so this file pins the recovery, not the removal.
//!
//! # The fixture is the shape the population measurement actually found
//!
//! Re-measuring `seed_path()` on a real host (dig-node#327) turned up a seed blob that is
//! **not** what the obvious fixture would have been:
//!
//! - the **legacy** `digstore_chain::seed::EncryptedSeed` layout (leading version byte `1`),
//!   not the current `DIGOP1` `dig-keystore` container;
//! - under a **`$HOME`-rooted** base rather than `%LOCALAPPDATA%`, so a Windows build does
//!   not resolve it by default;
//! - with **no `wallet.meta.json`** and **no device key** beside it — an origin-keyed count
//!   cannot classify it, and a device-key open cannot read it.
//!
//! Both of the nearest wrong implementations pass a friendlier fixture and fail this one: a
//! rescue that reads only the current container cannot decrypt a legacy blob, and a rescue
//! that resolves the default path itself cannot reach a file under a foreign base. Testing
//! either property alone leaves the other free, which is why the fixture carries both.
//!
//! # It runs the CLI, not the library function
//!
//! `dig_wallet::seed_export::export_mnemonic` being correct says nothing about whether any
//! shipped command reaches it. This drives `dign wallet export-seed` as a process, so the
//! argument routing and the password read are covered too.

use std::io::Write;
use std::process::{Command, Stdio};

/// A valid BIP-39 phrase. Test material only — it has never held funds.
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon art";

const PASSWORD: &str = "the-users-own-password";

#[test]
fn a_legacy_seed_under_a_foreign_base_is_still_recoverable_through_the_cli() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A base directory this build never resolves on its own, standing in for the `$HOME`
    // rooted layout the measurement found on a Windows host.
    let home = dir.path().join("some-other-home").join("DigWallet");
    std::fs::create_dir_all(&home).expect("create fixture dir");
    let seed = home.join("seed.bin");

    let legacy = digstore_chain::seed::encrypt_seed(PHRASE, PASSWORD).expect("legacy encrypt");
    let bytes = legacy.to_bytes();
    assert_eq!(
        bytes[0], 1,
        "fixture must be the LEGACY layout: a DIGOP1 container would not exercise the \
         format-dispatch this test exists to cover"
    );
    // No sidecar and no device key are written on purpose — see the module docs.
    assert!(!home.join("wallet.meta.json").exists());
    std::fs::write(&seed, &bytes).expect("write fixture seed");

    let mut child = Command::new(env!("CARGO_BIN_EXE_dign"))
        .args(["wallet", "export-seed", "--path"])
        .arg(&seed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dign wallet export-seed");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .expect("pipe the password");
    let out = child.wait_with_output().expect("wait for dign");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "export must succeed on a legacy seed at an explicit path; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        stdout.trim(),
        PHRASE,
        "the recovered phrase must be byte-identical to the one sealed"
    );
    // The file is a user's only copy; a rescue that consumed it would be a data-loss bug.
    assert_eq!(
        std::fs::read(&seed).expect("seed still readable"),
        bytes,
        "export must leave the seed file byte-identical"
    );
}

/// The negative control. Without it the test above cannot distinguish "the password was
/// checked" from "any input is accepted", and a rescue that ignored the password would pass
/// it — which is the failure mode that matters most on a file holding spend authority.
#[test]
fn a_wrong_password_is_refused_and_prints_no_phrase() {
    let dir = tempfile::tempdir().expect("temp dir");
    let seed = dir.path().join("seed.bin");
    let legacy = digstore_chain::seed::encrypt_seed(PHRASE, PASSWORD).expect("legacy encrypt");
    std::fs::write(&seed, legacy.to_bytes()).expect("write fixture seed");

    let mut child = Command::new(env!("CARGO_BIN_EXE_dign"))
        .args(["wallet", "export-seed", "--path"])
        .arg(&seed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dign wallet export-seed");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"not-the-password\n")
        .expect("pipe the password");
    let out = child.wait_with_output().expect("wait for dign");

    assert!(!out.status.success(), "a wrong password must not succeed");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !both.contains("abandon"),
        "no fragment of the phrase may appear on a failure path"
    );
}
