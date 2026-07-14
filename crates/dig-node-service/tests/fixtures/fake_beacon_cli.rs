//! A stand-in for the real `dig-updater` beacon CLI, used ONLY by the `control.updater.*`
//! control-plane tests (#515). The real binary lives in the separate `DIG-Network/dig-updater`
//! release and is not vendored here; this fixture reproduces just enough of its `--json` I/O
//! contract (SPEC §13.3 of that repo: a command prints one JSON object to stdout and exits zero
//! on success, non-zero on failure) so the tests exercise a REAL child-process spawn — not a
//! mock of [`std::process::Command`] itself.
//!
//! Named `fake_beacon_cli` (not `fake-dig-updater`) DELIBERATELY: Windows' installer-detection
//! heuristic can refuse to launch (`ERROR_ELEVATION_REQUIRED`, 740) an unmanifested `.exe` whose
//! name contains "update"/"install"/"setup"/"patch" — hit empirically while developing #515.
//!
//! Entirely driven by environment variables, set by the test right before it runs:
//!
//! - `FAKE_UPDATER_STDOUT` — the exact bytes to print to stdout (default `{}`).
//! - `FAKE_UPDATER_EXIT_CODE` — the process exit code (default `0`).
//! - `FAKE_UPDATER_ARGS_FILE` — when set, the argv this process received (space-joined) is
//!   written there, so a test can assert the caller built the right command line.

use std::io::Write;

fn main() {
    let stdout = std::env::var("FAKE_UPDATER_STDOUT").unwrap_or_else(|_| "{}".to_string());
    let exit_code: i32 = std::env::var("FAKE_UPDATER_EXIT_CODE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if let Ok(args_file) = std::env::var("FAKE_UPDATER_ARGS_FILE") {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        if let Ok(mut f) = std::fs::File::create(args_file) {
            let _ = f.write_all(argv.join(" ").as_bytes());
        }
    }

    println!("{stdout}");
    std::process::exit(exit_code);
}
