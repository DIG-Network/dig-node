//! `dig-node pair` — the OPERATOR side of the #280 control-token pairing flow.
//!
//! A thin loopback JSON-RPC client: it reads the master control token (proving
//! local-machine control) and drives the running node's gated `control.pairing.*`
//! methods so a browser controller (the DIG Chrome extension) can be granted a
//! scoped, revocable token after LOCAL confirmation.
//!
//! Subcommands (see `main.rs`):
//!   * `dig-node pair` / `dig-node pair list` — show pending pairing requests (each
//!     with the code the extension displays) + the issued controller tokens.
//!   * `dig-node pair approve <pairing_id>` — approve a pending request (mint a token).
//!     The operator FIRST confirms the printed `pairing_code` matches what the
//!     extension shows (compare-codes consent), then approves.
//!   * `dig-node pair revoke <token_id>` — revoke an issued controller token.
//!
//! Everything here reaches the node over `POST /` on its loopback address with the
//! `X-Dig-Control-Token` header — the same authorized surface the DIG Browser uses.

use serde_json::{json, Value};

use crate::cli::Outcome;
use crate::config::Config;
use crate::control_client::call_control;

/// The operator action, clap-agnostic (mapped from the CLI subcommand in `main.rs`).
pub enum PairAction {
    /// List pending requests + issued tokens (the default `dig-node pair`).
    List,
    /// Approve a pending pairing by id.
    Approve { pairing_id: String },
    /// Revoke an issued controller token by id.
    Revoke { token_id: String },
}

/// Run a `pair` subcommand: read the master token, call the node's `control.pairing.*`,
/// render an [`Outcome`]. The loopback transport + master-token auth is the shared
/// [`call_control`] client. Errors (node unreachable, bad id) surface as `io::Error` so
/// `main.rs` maps them to the differentiated exit code.
pub fn run(config: &Config, action: PairAction) -> std::io::Result<Outcome> {
    match action {
        PairAction::List => {
            let result = call_control(config, "control.pairing.list", json!({}))?;
            Ok(Outcome::new(format_list(&result), result))
        }
        PairAction::Approve { pairing_id } => {
            let result = call_control(
                config,
                "control.pairing.approve",
                json!({ "pairing_id": pairing_id }),
            )?;
            let name = result["client_name"].as_str().unwrap_or("controller");
            let tid = result["token_id"].as_str().unwrap_or("");
            Ok(Outcome::new(
                format!(
                    "dig-node: approved pairing for \"{name}\" — issued controller token {tid}.\n\
                     The extension's poll will now receive its scoped token. Revoke anytime with \
                     `dig-node pair revoke {tid}`."
                ),
                result,
            ))
        }
        PairAction::Revoke { token_id } => {
            let result = call_control(
                config,
                "control.pairing.revoke",
                json!({ "token_id": token_id }),
            )?;
            let revoked = result["revoked"].as_bool().unwrap_or(false);
            let summary = if revoked {
                format!("dig-node: revoked controller token {token_id}.")
            } else {
                format!("dig-node: no controller token with id {token_id} (nothing revoked).")
            };
            Ok(Outcome::new(summary, result))
        }
    }
}

/// Render `control.pairing.list` as an operator-friendly summary.
fn format_list(result: &Value) -> String {
    let mut out = String::new();
    let pending = result["pending"].as_array().cloned().unwrap_or_default();
    if pending.is_empty() {
        out.push_str("dig-node: no pending pairing requests.\n");
    } else {
        out.push_str(
            "Pending pairing requests (confirm the code matches the extension, then approve):\n",
        );
        for p in &pending {
            out.push_str(&format!(
                "  • {}  code {}  \"{}\"\n      approve: dig-node pair approve {}\n",
                p["pairing_id"].as_str().unwrap_or("?"),
                p["pairing_code"].as_str().unwrap_or("??????"),
                p["client_name"].as_str().unwrap_or("controller"),
                p["pairing_id"].as_str().unwrap_or("?"),
            ));
        }
    }
    let tokens = result["tokens"].as_array().cloned().unwrap_or_default();
    if tokens.is_empty() {
        out.push_str("dig-node: no issued controller tokens.");
    } else {
        out.push_str("Issued controller tokens (revoke with `dig-node pair revoke <id>`):\n");
        for t in &tokens {
            out.push_str(&format!(
                "  • {}  \"{}\"\n",
                t["id"].as_str().unwrap_or("?"),
                t["client_name"].as_str().unwrap_or("controller"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_list_reports_nothing_when_empty() {
        let s = format_list(&json!({ "pending": [], "tokens": [] }));
        assert!(s.contains("no pending pairing requests"));
        assert!(s.contains("no issued controller tokens"));
    }

    #[test]
    fn format_list_shows_codes_and_token_ids() {
        let s = format_list(&json!({
            "pending": [{ "pairing_id": "aabbccdd", "pairing_code": "481920",
                          "client_name": "DIG Chrome Extension" }],
            "tokens": [{ "id": "1234abcd", "client_name": "DIG Chrome Extension" }],
        }));
        // The operator sees the compare-codes value + the approve command + the token id.
        assert!(s.contains("481920"), "shows the pairing code to confirm");
        assert!(s.contains("dig-node pair approve aabbccdd"));
        assert!(
            s.contains("1234abcd"),
            "lists the issued token id for revoke"
        );
        // The token VALUE is never present (list never returns it).
        assert!(!s.contains("token\""));
    }
}
