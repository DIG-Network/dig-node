//! The advertised-TTL ↔ provider-record-lifetime coupling, enforced instead of commented (#1722).
//!
//! [`ADVERTISED_TTL_SECS`] is the `expires_at` this node claims on every opcode-222 `Add`. Whether
//! that claim is honoured depends on TWO dig-dht values it has no compile-time link to, and getting
//! either relation wrong fails SILENTLY — discovery goes intermittently lossy rather than visibly
//! broken, which is the worst shape a bug can take in a replication path.
//!
//! Until now the coupling was a doc-comment naming the symbol. A comment cannot fail, so a change on
//! either side would have shipped. These tests fail instead.
//!
//! # The two relations, which are NOT the same relation
//!
//! 1. **`advertised <= provider_ttl`** — the TRUNCATION bound. dig-dht clamps an ingested record to
//!    `min(record.expires_at, now + provider_ttl)`, so claiming longer than the receiver's TTL is
//!    silently cut back and the announcer's intent is lost. Current margin: 1h claimed against a 2h
//!    default — comfortable.
//!
//! 2. **`republish_interval <= advertised`** — the REFRESH bound. The holder re-announces every
//!    `republish_interval`; if a record expires before that fires, the holder vanishes from discovery
//!    until it does. Current margin: **ZERO** — dig-dht republishes hourly and this node advertises
//!    exactly one hour, so the record expires at the same instant the refresh is due.
//!
//! #1722 described "the margin" as zero, which is true of (2) and not of (1). Pinning only the
//! relation named in the ticket would have left the other unguarded, so both are pinned here.
//!
//! The zero margin in (2) is deliberately NOT closed by this change — see
//! [`the_refresh_bound_holds_but_only_exactly`] for why that is a wire-behaviour decision rather
//! than a test fix.

use std::time::Duration;

use dig_dht::DhtConfig;
use dig_node_core::seams::dig_peer::holdings::ADVERTISED_TTL_SECS;

/// Why an advertised TTL is unsound against a given pair of dig-dht intervals, or `Ok`.
///
/// A PURE predicate over all three values, rather than three inline assertions on the real
/// constants, so the rule can be exercised at and past each bound. Asserting only the real values
/// would confirm today's numbers without proving the check can fail at all — and a bound tested from
/// one side only can never distinguish a real guard from a tautology.
fn advertised_ttl_is_sound(
    advertised: Duration,
    provider_ttl: Duration,
    republish_interval: Duration,
) -> Result<(), String> {
    if advertised > provider_ttl {
        return Err(format!(
            "advertised {advertised:?} exceeds provider_ttl {provider_ttl:?}: every claim would be \
             silently clamped to the shorter lifetime"
        ));
    }
    if republish_interval > advertised {
        return Err(format!(
            "republish_interval {republish_interval:?} exceeds advertised {advertised:?}: records \
             expire before the holder re-announces, so discovery loses the holder periodically"
        ));
    }
    Ok(())
}

/// The advertised TTL as a [`Duration`], so it compares directly against dig-dht's fields.
fn advertised() -> Duration {
    Duration::from_secs(ADVERTISED_TTL_SECS)
}

/// **Proves:** the REAL `ADVERTISED_TTL_SECS` is sound against the REAL `DhtConfig::default()` —
/// both relations at once, read from dig-dht itself rather than from a number copied into a comment.
///
/// **Catches:** a change on EITHER side of a coupling that has no compile-time link. Lowering
/// dig-dht's `provider_ttl` below one hour, raising its `republish_interval` above one hour, or
/// moving `ADVERTISED_TTL_SECS` in either direction all fail here. That is the whole point: this is
/// the only thing in the tree that would notice.
#[test]
fn the_advertised_ttl_is_sound_against_dig_dhts_real_defaults() {
    let config = DhtConfig::default();
    assert_eq!(
        advertised_ttl_is_sound(advertised(), config.provider_ttl, config.republish_interval),
        Ok(()),
        "advertised={:?} provider_ttl={:?} republish_interval={:?}",
        advertised(),
        config.provider_ttl,
        config.republish_interval
    );
}

/// **Proves:** the truncation bound is enforced from BOTH sides — at the bound it passes, one second
/// over it fails.
///
/// **Catches:** the predicate degrading into something that cannot fail (a `>=` flipped, a
/// comparison dropped). A guard asserted only on values that satisfy it proves nothing about the
/// guard.
///
/// The one-second step is chosen over a round number on purpose: the bound is `<=`, so equality must
/// PASS and the very next representable value must FAIL. A test that overshot by an hour would still
/// pass against a predicate with an off-by-one in it.
#[test]
fn the_truncation_bound_is_enforced_from_both_sides() {
    let provider_ttl = Duration::from_secs(7_200);
    let republish = Duration::from_secs(3_600);

    assert_eq!(
        advertised_ttl_is_sound(provider_ttl, provider_ttl, republish),
        Ok(()),
        "advertising EXACTLY provider_ttl is sound — the clamp is a no-op at equality"
    );

    let one_over = provider_ttl + Duration::from_secs(1);
    let err = advertised_ttl_is_sound(one_over, provider_ttl, republish)
        .expect_err("advertising one second beyond provider_ttl must be rejected");
    assert!(
        err.contains("silently clamped"),
        "expected the truncation diagnosis, got: {err}"
    );
}

/// **Proves:** the refresh bound holds for the real values, and holds ONLY EXACTLY — one second more
/// republish interval fails.
///
/// **Catches:** dig-dht raising `republish_interval` above an hour, which would put this node's
/// records in a permanent expire-then-refresh flap. It also records the finding in an executable
/// form: the assertion below states that the current values sit exactly ON the bound, so if anyone
/// later adds margin on either side, this test fails and forces them to update the recorded
/// relationship rather than leaving a stale claim behind.
///
/// **Deliberately NOT fixed here.** Closing the margin means either advertising longer (up to
/// dig-dht's 2h `provider_ttl`, which gains an hour of refresh margin but is then clamped for any
/// receiver configured BELOW 2h — and `provider_ttl` is a config field, not a constant, so some
/// receiver being lower is a real possibility) or dig-dht republishing sooner (a change in another
/// repo, release-first). Both change on-wire behaviour, and they trade clamp-safety against
/// refresh-margin in opposite directions with no value satisfying both. That is a decision, not a
/// test fix, so #1722's mechanical pin lands here and the value choice is reported separately.
#[test]
fn the_refresh_bound_holds_but_only_exactly() {
    let config = DhtConfig::default();
    assert_eq!(
        config.republish_interval,
        advertised(),
        "the refresh margin is currently ZERO by measurement, not by design — dig-dht republishes \
         every {:?} and this node advertises {:?}. If either moved, update this recorded \
         relationship (#1722) rather than relaxing the assertion.",
        config.republish_interval,
        advertised()
    );

    let one_over = advertised() + Duration::from_secs(1);
    let err = advertised_ttl_is_sound(advertised(), config.provider_ttl, one_over)
        .expect_err("a republish interval one second past the advertised TTL must be rejected");
    assert!(
        err.contains("expire before the holder re-announces"),
        "expected the refresh diagnosis, got: {err}"
    );
}
