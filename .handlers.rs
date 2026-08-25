
// -- Coin reservations (dig_ecosystem#3127) ----------------------------------
//
// The cross-process half of coin reservation. dig-account holds the wallet-layer seam for callers
// inside ONE process; these three methods let a SECOND process — dig-app, over this control
// interface — narrow against the same set, so two processes sharing one wallet cannot select the
// same coin.
//
// Authority is settled and normative (SPEC §18.25.1): where a node is reachable, THIS node's set
// is authoritative and a client defers to it. A client-local set is the no-node fallback only.
//
// §908 binds all three: reservation is BOOKKEEPING. A coin id is a public chain fact; nothing here
// holds a key, signs anything, or authorizes anything.

/// `control.wallet.reservations.held` — the coins committed to in-flight spends.
///
/// Takes no parameters on purpose. A caller-supplied instant would be a lapse oracle: a far-future
/// value makes every live hold read as expired, which is a free way to defeat the whole set. The
/// node reads its OWN clock and reports it as `as_of_unix` so a client can see skew rather than
/// impose it.
///
/// TOKEN-GATED although it is a read, for the same reason as `control.wallet.watched`: the caller
/// supplies nothing, so the answer describes this node's own state rather than a public chain fact
/// the caller already named.
///
/// A read failure is `WALLET_RESERVATIONS_UNAVAILABLE`, NEVER an empty list. `reserved: []` is a
/// positive statement that nothing is held and permits a caller to spend; "I cannot tell" must
/// stop one. Collapsing the two restores the double-select this exists to prevent.
async fn wallet_reservations_held(ctx: &ControlCtx, id: Value) -> Value {
    match ctx.wallet.reservations_held().await {
        Ok((rows, now_ms)) => control_ok(
            id,
            json!({
                "reserved": rows
                    .iter()
                    .map(|r| json!({
                        "coin_id": r.coin_id,
                        "reservation_id": r.reservation_id,
                        "expires_at_unix": ms_to_unix(r.expires_at_ms),
                    }))
                    .collect::<Vec<_>>(),
                "as_of_unix": ms_to_unix(now_ms),
            }),
        ),
        Err(e) => reservations_unavailable(id, &e),
    }
}

/// `control.wallet.reservations.reserve` — atomically hold coins, all of them or none.
///
/// A clash is `WALLET_COINS_RESERVED`, deliberately distinct from any shortfall: the user HAS the
/// money, it is briefly committed elsewhere, and it returns when that spend settles or its hold
/// lapses. Reporting insufficient funds would send a person to an exchange to solve a wait.
///
/// The returned `ttl_secs` is the lifetime this node APPLIED, which may be shorter than the one
/// requested — a caller told its own figure would wait on a schedule this node does not keep.
async fn wallet_reservations_reserve(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.reservations.reserve";

    // An ABSENT `coin_ids` is malformed, while an EMPTY one is a legitimate no-op that yields a
    // handle holding nothing. Defaulting the absent case to empty would turn a client bug into a
    // silent success, so the two are kept apart.
    let Some(raw) = params.get("coin_ids") else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.coin_ids is required"),
        );
    };
    let Some(items) = raw.as_array() else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.coin_ids must be an array of coin-id strings"),
        );
    };
    let mut coin_ids = Vec::with_capacity(items.len());
    for item in items {
        let Some(s) = item.as_str() else {
            return control_error(
                id,
                ErrorCode::InvalidParams,
                format!("{METHOD}: every params.coin_ids entry must be a string"),
            );
        };
        coin_ids.push(s.to_string());
    }

    let ttl_secs = match params.get("ttl_secs") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(n) => Some(n),
            None => {
                return control_error(
                    id,
                    ErrorCode::InvalidParams,
                    format!("{METHOD}: params.ttl_secs must be a non-negative integer"),
                );
            }
        },
    };

    match ctx.wallet.reserve_coins(&coin_ids, ttl_secs).await {
        Ok(r) => control_ok(
            id,
            json!({
                "reservation_id": r.reservation_id,
                "coin_ids": r.coin_ids,
                "expires_at_unix": ms_to_unix(r.expires_at_ms),
                // The lifetime the node APPLIED, reported by the same call that applied it.
                // Echoing the caller's request is how a client ends up scheduling a release
                // against a lifetime this node never granted.
                "ttl_secs": (r.ttl_ms.max(0) as u64) / 1000,
            }),
        ),
        Err(ReserveClientCoinsError::Reserved { coin_ids }) => control_error(
            id,
            ErrorCode::WalletCoinsReserved,
            format!(
                "{} coin(s) are committed to a live spend; nothing was reserved. This is a wait, \
                 not a shortfall",
                coin_ids.len()
            ),
        ),
        Err(ReserveClientCoinsError::Unavailable(e)) => reservations_unavailable(id, &e),
    }
}

/// `control.wallet.reservations.release` — free a hold now, ahead of its TTL.
///
/// A handle naming no live reservation is a SUCCESS with `released: false`. A caller releasing on
/// confirmation cannot know whether the TTL got there first, and making the ordinary outcome an
/// error teaches callers to stop checking the result — which is how a release path quietly stops
/// being called, and a release path that stops being called is a funds lockout waiting to happen.
async fn wallet_reservations_release(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.reservations.release";
    let Some(handle) = params.get("reservation_id").and_then(Value::as_str) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.reservation_id is required and must be a string"),
        );
    };
    match ctx.wallet.release_reservation(handle).await {
        Ok(coin_ids) => control_ok(
            id,
            json!({ "released": !coin_ids.is_empty(), "coin_ids": coin_ids }),
        ),
        Err(e) => reservations_unavailable(id, &e),
    }
}

/// The one fail direction for all three reservation methods: REFUSE.
///
/// The underlying error is deliberately NOT interpolated into the message. It is a database error
/// whose text can carry a file path, and a control response is a lower-trust surface than the log.
fn reservations_unavailable(id: Value, e: &sqlx::Error) -> Value {
    tracing::warn!(error = %e, "the coin-reservation set could not be read");
    control_error(
        id,
        ErrorCode::WalletReservationsUnavailable,
        "the node's coin-reservation set could not be read, so coin selection cannot be trusted",
    )
}

/// Milliseconds since the epoch to whole seconds, the unit the control contract speaks.
///
/// Saturating at zero rather than wrapping: a negative instant is not representable in the wire's
/// `u64`, and a wrap would turn a nonsense clock into a hold that reads as lasting for eons.
fn ms_to_unix(ms: i64) -> u64 {
    ms.max(0) as u64 / 1000
}
