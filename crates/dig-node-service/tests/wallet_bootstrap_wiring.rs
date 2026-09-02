//! The start-up seed check must actually be WIRED to start-up (#277).
//!
//! `wallet_bootstrap`'s own behaviour is covered by unit tests, but a correct function nobody calls
//! mints nothing. These guards pin the call sites, because the failure they prevent is silent: a
//! refactor that drops the call leaves every behavioural test green while the node quietly stops
//! creating wallets, and the symptom only appears on a fresh install months later.
//!
//! Source-shape guards, in the idiom this crate already uses for its release-workflow invariants —
//! the alternative is spawning a real service process, which cannot be done in a unit test without
//! writing to the machine's actual per-user wallet directory.

/// The foreground `run` path and the non-Windows service path both go through `block_on_serve`.
const ENTRYPOINT: &str = include_str!("../src/entrypoint.rs");
/// The Windows SCM path does NOT go through `block_on_serve`, so it carries its own call.
const WIN_SERVICE: &str = include_str!("../src/win_service.rs");
/// The HTTP server function, which must NOT carry the call. See below.
const SERVER: &str = include_str!("../src/server.rs");

/// The exact call the guards look for.
const CALL: &str = "wallet_bootstrap::ensure_wallet_seed()";

/// The environment announcement that must run BEFORE the bootstrap on every serve entrypoint
/// (#392). Guarded for the same reason as `CALL`: an announcement present on only one of the two
/// entrypoints is silent on exactly the unattended service run nobody is watching, and no
/// behavioural test can see that - `announce_from_env` is correct in isolation either way.
const ANNOUNCE: &str = "wallet_env::announce_from_env()";

/// **Proves:** the foreground entrypoint checks for a seed on start.
#[test]
fn the_foreground_entrypoint_ensures_a_wallet_seed() {
    let body = between(ENTRYPOINT, "fn block_on_serve(", "\n}\n").expect("block_on_serve exists");
    assert!(
        body.contains(CALL),
        "`block_on_serve` must ensure a wallet seed on every start (#277); it is the entrypoint \
         for `dig-node run` and for the non-Windows service"
    );
}

/// **Proves:** the foreground entrypoint says what it resolved before it mints anything.
///
/// Order matters and is asserted: an operator must read WHY a wallet was refused before, not
/// after, the line that would otherwise have reported one minted.
#[test]
fn the_foreground_entrypoint_announces_the_wallet_environment_first() {
    let body = between(
        ENTRYPOINT,
        "fn block_on_serve(",
        "
}
",
    )
    .expect("block_on_serve exists");
    let announce = body.find(ANNOUNCE).expect(
        "`block_on_serve` must announce the resolved wallet environment on every start (#392)",
    );
    let bootstrap = body.find(CALL).expect("and it must still bootstrap");
    assert!(
        announce < bootstrap,
        "the announcement must precede the mint, or the refusal is explained after the fact (#392)"
    );
}

/// **Proves:** the Windows SCM entrypoint announces too.
///
/// It does not share `block_on_serve`, so it carries its own call - and it is the unattended path,
/// where a missing warning has nobody to notice it.
#[test]
fn the_windows_service_entrypoint_announces_the_wallet_environment_first() {
    let announce = WIN_SERVICE
        .find(ANNOUNCE)
        .expect("the Windows SCM entrypoint must announce the wallet environment (#392)");
    let bootstrap = WIN_SERVICE.find(CALL).expect("and must still bootstrap");
    assert!(
        announce < bootstrap,
        "the announcement must precede the mint on the SCM path too (#392)"
    );
}

/// **Proves:** the Windows service entrypoint checks too.
///
/// A separate assertion rather than a repo-wide grep, because this is the path where the guarantee
/// matters most and the one most easily missed: it does not share `block_on_serve`, and a service
/// install is precisely the case with no user present to create a seed by hand.
#[test]
fn the_windows_service_entrypoint_ensures_a_wallet_seed() {
    assert!(
        WIN_SERVICE.contains(CALL),
        "the Windows SCM entrypoint must ensure a wallet seed on every start (#277)"
    );
}

/// **Proves:** the HTTP server function does NOT mint wallets.
///
/// This guard exists because the call lived there first, and the consequence was concrete: the
/// server integration suite drives `serve_with_shutdown` dozens of times, the bootstrap resolves
/// the REAL per-user `%LOCALAPPDATA%`, and so `cargo test` minted a wallet into the developer's own
/// profile. Minting belongs to the process lifecycle, not to a function tests instantiate freely.
#[test]
fn the_http_server_function_does_not_mint_wallets() {
    assert!(
        !SERVER.contains(CALL),
        "server.rs must not ensure a wallet seed — the integration tests drive it directly and \
         would write to the real user profile (#277)"
    );
}

/// Return the text between `start` and the following `end`, so a guard reads one function rather
/// than the whole file.
fn between<'a>(haystack: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = haystack.find(start)?;
    let rest = &haystack[from..];
    let to = rest.find(end)? + end.len();
    Some(&rest[..to])
}
