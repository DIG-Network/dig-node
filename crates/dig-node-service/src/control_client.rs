//! The shared OPERATOR-side loopback JSON-RPC client for the gated `control.*` surface.
//!
//! Every CLI subcommand that drives a `control.*` method — `pair` (#280), and the
//! control-parity commands (`cache`/`stores`/`sync`/`config`/`updater`/`subscriptions`/
//! `info`, #426) + `peers` (#559) — reaches the running node through THIS one client, so
//! there is exactly ONE codepath for "read the master control token, POST a control method
//! to loopback, unwrap the result". No subcommand forks the transport or the auth.
//!
//! # Auth — the SAME gate the extension uses (never a backdoor)
//!
//! The client presents the node's MASTER control token — read WITHOUT minting one
//! ([`crate::control::load_token_readonly`], #501) — as the `X-Dig-Control-Token` header on
//! `POST /`. This is the exact authorized surface the DIG Browser / extension speak
//! ([`crate::control`]); possession of the on-disk master token = local-machine control, so a
//! mutating CLI control is gated by the same capability as the WS, not an unauthenticated side
//! door. A node running as a service under another OS account surfaces the precise
//! service-vs-user remedy from `load_token_readonly` (elevate / grant read ACL / start the node).

use serde_json::{json, Value};

use crate::config::Config;
use crate::control;

/// Call one `control.*` method on the running node and return its `result` object.
///
/// Reads the master control token read-only, builds a single-shot current-thread runtime,
/// and POSTs the JSON-RPC request to the node's loopback address. Every failure surfaces as
/// an [`std::io::Error`] whose KIND maps to the differentiated CLI exit code
/// ([`crate::cli::ExitCode::from_io_error`]): a transport failure → `ConnectionRefused`
/// ("is the node running?"), a JSON-RPC `error` → `Other` (the node's own message).
pub fn call_control(config: &Config, method: &str, params: Value) -> std::io::Result<Value> {
    let addr = config.bind_addr();
    let token = control::load_token_readonly()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(call_async(&addr, &token, method, params))
}

/// POST one JSON-RPC control method with the master token; return its `result` (or `{}` when
/// the node omits one). A transport failure = the node isn't running; a JSON-RPC `error` =
/// the node rejected the call (e.g. a method it does not implement → METHOD_NOT_FOUND).
async fn call_async(
    addr: &str,
    token: &str,
    method: &str,
    params: Value,
) -> std::io::Result<Value> {
    let client = reqwest::Client::builder()
        .build()
        .map_err(std::io::Error::other)?;
    let url = format!("http://{addr}/");
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = client
        .post(&url)
        .header(control::CONTROL_TOKEN_HEADER, token)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!(
                    "could not reach the dig-node at {url}: {e} — is it running? \
                     Start it with `dig-node run` (or `dig-node start` for the service)."
                ),
            )
        })?;
    let v: Value = resp.json().await.map_err(std::io::Error::other)?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown control error");
        return Err(std::io::Error::other(format!("dig-node: {msg}")));
    }
    Ok(v.get("result").cloned().unwrap_or_else(|| json!({})))
}
