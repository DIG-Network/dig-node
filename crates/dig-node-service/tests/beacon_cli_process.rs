//! Wired tests for the beacon (`dig-updater`) RPC proxy (#515) that need a REAL child-process
//! spawn: `control.updater.setChannel`/`pause`/`resume`/`checkNow` run against the
//! `fake_beacon_cli` fixture binary (`tests/fixtures/fake_beacon_cli.rs`), a stand-in for the
//! real `dig-updater` CLI's `--json` I/O contract (dig-updater SPEC §13.3).
//!
//! `dig_node_service::updater`'s own unit tests (`src/updater.rs`) cover `status.json` handling,
//! param validation, and binary resolution WITHOUT spawning anything; these prove the spawn +
//! parse plumbing itself over a real OS process boundary — argv, stdout, and exit code. The full
//! HTTP wire path (the control-token auth gate -> dispatch -> this proxy) is covered separately
//! in `tests/server.rs`.
//!
//! `env!("CARGO_BIN_EXE_fake_beacon_cli")` — the path to the fixture binary Cargo built
//! alongside this test target — is only available in an INTEGRATION test file like this one,
//! which is why these live here rather than in `src/updater.rs`'s own `#[cfg(test)]` module.
//! (The fixture is deliberately NOT named after "dig-updater" — see its own doc comment.)

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use dig_node_service::updater::{check_now, pause, resume, set_channel, CLI_BIN_ENV};
use serde_json::json;
use tokio::sync::Mutex;

/// Serializes these tests against each other — they all mutate the SAME process-global
/// `DIG_UPDATER_BIN`/`FAKE_UPDATER_*` env vars the fixture reads. A `tokio::sync::Mutex` (not
/// `std::sync::Mutex`): every test here holds the guard across an `.await`, which trips
/// `clippy::await_holding_lock` on a std guard.
fn env_guard() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A unique-per-call scratch path for the fixture's `FAKE_UPDATER_ARGS_FILE` capture.
fn unique_path(label: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "dig-node-updater-cli-test-{label}-{}-{n}",
        std::process::id()
    ))
}

fn fake_cli_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake_beacon_cli"))
}

fn clear_fixture_env() {
    for var in [
        CLI_BIN_ENV,
        "FAKE_UPDATER_STDOUT",
        "FAKE_UPDATER_EXIT_CODE",
        "FAKE_UPDATER_ARGS_FILE",
    ] {
        std::env::remove_var(var);
    }
}

#[tokio::test]
async fn set_channel_runs_the_cli_and_returns_its_json_verbatim() {
    let _guard = env_guard().lock().await;
    clear_fixture_env();
    std::env::set_var(CLI_BIN_ENV, fake_cli_path());
    std::env::set_var(
        "FAKE_UPDATER_STDOUT",
        r#"{"command":"channel","channel":"alpha"}"#,
    );
    let args_file = unique_path("args-setchannel");
    std::env::set_var("FAKE_UPDATER_ARGS_FILE", &args_file);

    let resp = set_channel(json!(1), &json!({ "channel": "alpha" })).await;

    assert_eq!(resp["result"]["channel"], json!("alpha"));
    assert_eq!(
        std::fs::read_to_string(&args_file).unwrap(),
        "channel set alpha --json",
        "the exact argv dig-updater received"
    );

    let _ = std::fs::remove_file(&args_file);
    clear_fixture_env();
}

/// The proxy is a THIN passthrough (#605): whatever channel token the controller sends is
/// forwarded VERBATIM to `dig-updater channel set <token> --json`. The beacon CLI — never this
/// proxy — is the single validation surface, so the proxy carries `nightly`, `stable`, and the
/// deprecated `alpha` alias identically, with no enum of its own to drift from the beacon's
/// (dig-updater's `Channel`: `nightly | stable`, `alpha` ≡ `nightly`, default `stable`).
#[tokio::test]
async fn set_channel_forwards_every_channel_token_verbatim() {
    let _guard = env_guard().lock().await;
    for channel in ["nightly", "stable", "alpha"] {
        clear_fixture_env();
        std::env::set_var(CLI_BIN_ENV, fake_cli_path());
        std::env::set_var(
            "FAKE_UPDATER_STDOUT",
            format!(r#"{{"command":"channel","channel":"{channel}"}}"#),
        );
        let args_file = unique_path(&format!("args-setchannel-{channel}"));
        std::env::set_var("FAKE_UPDATER_ARGS_FILE", &args_file);

        let resp = set_channel(json!(1), &json!({ "channel": channel })).await;

        assert_eq!(resp["result"]["channel"], json!(channel));
        assert_eq!(
            std::fs::read_to_string(&args_file).unwrap(),
            format!("channel set {channel} --json"),
            "the {channel} token must reach dig-updater verbatim"
        );

        let _ = std::fs::remove_file(&args_file);
    }
    clear_fixture_env();
}

#[tokio::test]
async fn pause_with_until_passes_the_flag_through() {
    let _guard = env_guard().lock().await;
    clear_fixture_env();
    std::env::set_var(CLI_BIN_ENV, fake_cli_path());
    std::env::set_var(
        "FAKE_UPDATER_STDOUT",
        r#"{"command":"pause","paused":true,"paused_until":500}"#,
    );
    let args_file = unique_path("args-pause");
    std::env::set_var("FAKE_UPDATER_ARGS_FILE", &args_file);

    let resp = pause(json!(1), &json!({ "until": 500 })).await;

    assert_eq!(resp["result"]["paused"], json!(true));
    assert_eq!(resp["result"]["paused_until"], json!(500));
    assert_eq!(
        std::fs::read_to_string(&args_file).unwrap(),
        "pause --until 500 --json"
    );

    let _ = std::fs::remove_file(&args_file);
    clear_fixture_env();
}

#[tokio::test]
async fn resume_runs_with_no_extra_flags() {
    let _guard = env_guard().lock().await;
    clear_fixture_env();
    std::env::set_var(CLI_BIN_ENV, fake_cli_path());
    std::env::set_var(
        "FAKE_UPDATER_STDOUT",
        r#"{"command":"pause","paused":false,"paused_until":null}"#,
    );
    let args_file = unique_path("args-resume");
    std::env::set_var("FAKE_UPDATER_ARGS_FILE", &args_file);

    let resp = resume(json!(1)).await;

    assert_eq!(resp["result"]["paused"], json!(false));
    assert_eq!(
        std::fs::read_to_string(&args_file).unwrap(),
        "resume --json"
    );

    let _ = std::fs::remove_file(&args_file);
    clear_fixture_env();
}

#[tokio::test]
async fn check_now_forwards_the_pass_report_on_success() {
    let _guard = env_guard().lock().await;
    clear_fixture_env();
    std::env::set_var(CLI_BIN_ENV, fake_cli_path());
    std::env::set_var(
        "FAKE_UPDATER_STDOUT",
        r#"{"applied":false,"reason":"paused","detail":null,"components":[],"state_advanced":false}"#,
    );
    let args_file = unique_path("args-checknow");
    std::env::set_var("FAKE_UPDATER_ARGS_FILE", &args_file);

    let resp = check_now(json!(1)).await;

    assert_eq!(resp["result"]["applied"], json!(false));
    assert_eq!(resp["result"]["reason"], json!("paused"));
    assert_eq!(
        std::fs::read_to_string(&args_file).unwrap(),
        "check --now --json"
    );

    let _ = std::fs::remove_file(&args_file);
    clear_fixture_env();
}

/// A garbage channel token is still forwarded verbatim (the proxy does not pre-validate — #605);
/// the beacon CLI is the sole validator, and its decline surfaces through the existing
/// exit-code + `detail` classification as a `CONTROL_ERROR`. (`nightly`/`stable`/`alpha` are the
/// only tokens the beacon accepts; anything else — like this `banana` — is declined there.)
#[tokio::test]
async fn a_declined_cli_run_surfaces_its_detail_as_a_control_error() {
    let _guard = env_guard().lock().await;
    clear_fixture_env();
    std::env::set_var(CLI_BIN_ENV, fake_cli_path());
    std::env::set_var(
        "FAKE_UPDATER_STDOUT",
        r#"{"status":"error","detail":"unknown channel 'banana'"}"#,
    );
    std::env::set_var("FAKE_UPDATER_EXIT_CODE", "2");

    let resp = set_channel(json!(1), &json!({ "channel": "banana" })).await;

    assert_eq!(resp["error"]["data"]["code"], json!("CONTROL_ERROR"));
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("banana"));

    clear_fixture_env();
}

#[tokio::test]
async fn a_crashing_cli_is_reported_as_malformed_not_silently_swallowed() {
    let _guard = env_guard().lock().await;
    clear_fixture_env();
    std::env::set_var(CLI_BIN_ENV, fake_cli_path());
    std::env::set_var("FAKE_UPDATER_STDOUT", "this is not json");
    std::env::set_var("FAKE_UPDATER_EXIT_CODE", "101");

    let resp = check_now(json!(1)).await;

    assert_eq!(resp["error"]["data"]["code"], json!("CONTROL_ERROR"));
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unparsable"));

    clear_fixture_env();
}
