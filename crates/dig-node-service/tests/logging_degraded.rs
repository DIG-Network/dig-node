//! The property the `dig-logging` 0.2.0 adoption exists for: when the log directory cannot be
//! opened, the node still logs to stderr AND knows its file sink is off.
//!
//! Under `dig-logging` 0.1.x the same condition returned `Err` from `init`, so the console layer
//! was never installed and the process ran with NO tracing subscriber at all — an interactive
//! `dig-node run` on a host whose machine log dir belongs to the service account was completely
//! silent, which read as a dead subsystem rather than a broken one.
//!
//! ## Why this is an integration test, and why it is the whole file
//!
//! `tracing` has exactly ONE global subscriber per process and `logging::init` stores its guard
//! in a `OnceLock`, so the installed/degraded state can be established exactly once. This test
//! therefore owns its process: it sets `DIG_LOG_DIR` to an UNOPENABLE path before the only
//! `init` call, and every assertion reads that one outcome.
//!
//! The fixture is an unopenable directory in the strongest available sense: a path whose PARENT
//! is a regular FILE. `create_dir_all` cannot succeed under a file on any platform, so this does
//! not depend on running unprivileged, on ACLs, or on a read-only mount — the three things that
//! quietly make a permission fixture pass for the wrong reason (or, under a test runner elevated
//! to Administrator, not fail at all).

use std::io::Write;

use dig_logging::RunContext;
use dig_node_service::logging;
use tracing::level_filters::LevelFilter;

/// A log-dir root that cannot be created: a path nested inside a regular file.
///
/// The guard owns the scratch tree the blocking file sits in, so it is removed on drop and
/// on an unwind (dig-node#370); the caller holds it for the test's duration.
fn unopenable_log_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::Builder::new()
        .prefix("dig-node-logtest-")
        .tempdir()
        .expect("a scratch dir");
    let base = scratch.path().join("blocking-file");
    let mut file = std::fs::File::create(&base).expect("create the blocking regular file");
    file.write_all(b"not a directory").unwrap();
    let root = base.join("root");
    (scratch, root)
}

#[test]
fn unwritable_log_dir_leaves_console_logging_live_and_the_file_sink_reported_off() {
    let (_scratch, root) = unopenable_log_root();
    // SAFETY: single-threaded test body, set before the process's only `init`.
    unsafe { std::env::set_var("DIG_LOG_DIR", &root) };

    logging::init(RunContext::Cli);

    // (1) The console sink is live. With no subscriber installed — the 0.1.x outcome for this
    // exact input — `LevelFilter::current()` is `OFF`, so this assertion fails for the right
    // reason on the unadopted crate rather than merely compiling differently.
    assert!(
        logging::initialized(),
        "init must succeed and hold a guard even when the file sink cannot be opened"
    );
    assert_ne!(
        LevelFilter::current(),
        LevelFilter::OFF,
        "a subscriber must be installed, i.e. the node still logs to stderr"
    );

    // (2) The node KNOWS the file sink is off, and says why.
    let file_error = logging::file_error();
    assert!(
        file_error.is_some(),
        "an unopenable log dir must be reported via file_error(), got None (log_dir: {:?})",
        logging::log_dir()
    );

    // (3) The health surface `control.status` reports is consistent with (2): a degraded sink is
    // never dressed up as healthy file logging.
    let health = logging::health(
        logging::initialized(),
        logging::log_dir().as_deref(),
        file_error.as_deref(),
    );
    assert_eq!(health["initialized"], true);
    assert_eq!(health["file_logging"], false);
    assert!(health["file_error"].is_string());

    // Emitting through the live subscriber must not panic; this is the behaviour the silent-node
    // incident was missing.
    tracing::info!(test = "degraded", "node still speaks on the console");

    let _ = std::fs::remove_file(root.parent().unwrap());
}
