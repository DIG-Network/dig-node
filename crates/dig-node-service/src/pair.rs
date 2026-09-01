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

use crate::untrusted_text::render_untrusted;

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
            let name = render_untrusted(
                result["client_name"].as_str().unwrap_or("controller"),
                CLIENT_NAME_COLUMNS,
            );
            let tid = result["token_id"].as_str().unwrap_or("");
            Ok(Outcome::new(
                format!(
                    "dig-node: approved pairing for {name:?} — issued controller token {tid}.\n\
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

/// The display budget, in terminal columns, for an attacker-supplied `client_name`.
///
/// It matches `pairing::MAX_CLIENT_NAME`, so a name this node ACCEPTED renders unmarked and the
/// clip marker only ever appears on a value that arrived from somewhere else (a hand-edited
/// paired-token store, or a future ingest path). The marker therefore carries information.
const CLIENT_NAME_COLUMNS: usize = 64;

/// Render `control.pairing.list` as an operator-friendly summary.
///
/// Every `client_name` here is ATTACKER-SUPPLIED, because `pairing.request` is open and
/// unauthenticated, and it is composed into the sentence that gates a control-token grant. It
/// therefore goes through [`render_untrusted`] rather than into the format string directly
/// (dig-node#346).
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
                "  • {}  code {}  {:?}\n      approve: dig-node pair approve {}\n",
                p["pairing_id"].as_str().unwrap_or("?"),
                p["pairing_code"].as_str().unwrap_or("??????"),
                render_untrusted(
                    p["client_name"].as_str().unwrap_or("controller"),
                    CLIENT_NAME_COLUMNS,
                ),
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
                "  • {}  {:?}\n",
                t["id"].as_str().unwrap_or("?"),
                render_untrusted(
                    t["client_name"].as_str().unwrap_or("controller"),
                    CLIENT_NAME_COLUMNS,
                ),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves (dig-node#346):** an attacker-supplied `client_name` cannot forge a line of the
    /// operator's approval prompt.
    ///
    /// The prompt is line-oriented and the value is QUOTED rather than escaped, so a newline plus
    /// the prompt's own bullet shape prints a second, entirely attacker-written pending request in
    /// the node's voice — and the operator's only evidence about who is asking is this string.
    ///
    /// The assertion is on the LINE COUNT, not on the absence of a substring: a renderer that
    /// escaped the quotes but kept the newline would still have added a line, and a substring
    /// check would not see it.
    #[test]
    fn a_client_name_cannot_forge_an_extra_line_in_the_approval_prompt() {
        let forged = "Sage\n  \u{2022} deadbeef  code 000000  \"DIG Chrome Extension\"";
        let out = format_list(&json!({
            "pending": [{
                "pairing_id": "aabb",
                "pairing_code": "123456",
                "client_name": forged,
            }],
            "tokens": [],
        }));

        // The property is LINES, not bullets. A renderer that escaped the quotes but let the
        // newline through would still have added a line, and a substring check would not see it.
        //
        // The expected count is taken from the SAME render with a benign name rather than counted
        // by hand: hand-counting is how this assertion was wrong the first time, and a baseline
        // cannot drift when the prompt's own layout changes.
        let benign = format_list(&json!({
            "pending": [{
                "pairing_id": "aabb",
                "pairing_code": "123456",
                "client_name": "Sage",
            }],
            "tokens": [],
        }));
        assert_eq!(
            out.lines().count(),
            benign.lines().count(),
            "an attacker-supplied name must not change how many lines the prompt has:\n{out}"
        );
        // The slot is `{:?}`-quoted, so an embedded quote is escaped rather than terminating the
        // slot and letting the remainder read as the prompt's own words.
        assert!(
            !out.contains("\"DIG Chrome Extension\""),
            "the forged inner quotation must not survive unescaped:\n{out}"
        );

        // The two assertions above are satisfied by the `{:?}` QUOTING ALONE — measured, by
        // deleting `render_untrusted` from this call site and watching them both still pass. Debug
        // renders a newline as the two characters `\n`, which neither adds a line nor leaves the
        // quote unescaped, so they pin the quoting and say nothing about neutralisation.
        //
        // The replacement character is the discriminator Debug cannot supply: only
        // `render_untrusted` maps a forbidden character to a VISIBLE U+FFFD. Dropping the call
        // fails here.
        assert!(
            out.contains(crate::untrusted_text::REPLACEMENT),
            "the newline must be NEUTRALISED to a visible replacement, not merely escaped:\n{out}"
        );
        assert!(
            !out.contains("\\n"),
            "an escaped-but-surviving newline means the value was quoted rather than \
             neutralised:\n{out}"
        );
    }

    /// **Proves:** a clip in the operator prompt is MARKED, so the operator can tell a short name
    /// from a name the node made short.
    ///
    /// The paired-token store is on disk and is not bounded by `pairing::MAX_CLIENT_NAME`, so a
    /// value longer than the display budget can genuinely reach this renderer.
    #[test]
    fn an_over_budget_client_name_is_clipped_with_a_visible_mark() {
        let long = "x".repeat(400);

        // BOTH call sites, because they are separate `format!` arms: a test that read only one
        // could not see the other losing its neutralisation.
        let tokens = format_list(&json!({
            "pending": [],
            "tokens": [{ "id": "tok1", "client_name": long }],
        }));
        assert!(
            tokens.contains(crate::untrusted_text::CLIP_MARK),
            "a clipped token name must say the node clipped it:\n{tokens}"
        );

        let pending = format_list(&json!({
            "pending": [{
                "pairing_id": "aabb",
                "pairing_code": "123456",
                "client_name": long,
            }],
            "tokens": [],
        }));
        assert!(
            pending.contains(crate::untrusted_text::CLIP_MARK),
            "a clipped pending name must say the node clipped it:\n{pending}"
        );
    }

    /// **Proves:** a legitimate name renders EXACTLY, unmarked and unmangled.
    ///
    /// Without this control every assertion above is satisfied by a renderer that mangles
    /// everything, which would make the clip marker meaningless and the prompt unreadable.
    #[test]
    fn an_ordinary_client_name_renders_unchanged() {
        let out = format_list(&json!({
            "pending": [{
                "pairing_id": "aabb",
                "pairing_code": "123456",
                "client_name": "DIG Chrome Extension",
            }],
            "tokens": [],
        }));
        assert!(out.contains("\"DIG Chrome Extension\""), "{out}");
        assert!(!out.contains(crate::untrusted_text::CLIP_MARK), "{out}");
    }

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
