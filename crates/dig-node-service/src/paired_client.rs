//! The CLIENT half of the #280 control-token pairing handshake (dig-node#403).
//!
//! `pairing.rs` implements the node's side of the three steps; `pair.rs` implements the
//! OPERATOR's side (list / approve / revoke). Neither gives an ordinary, unprivileged OS user a
//! way to ASK for a token and KEEP it — so on a `.deb` install, where the master control token is
//! `0600 root:root` (#501), every `control.*` CLI verb was reachable only under `sudo`.
//!
//! This module closes that gap WITHOUT widening a single file mode:
//!
//! * [`select_token`] is the token LADDER — master token when readable, else the per-user paired
//!   token, else the master read's own rich remedy error, unchanged.
//! * [`paired_token_path`] / [`store_paired_token`] / [`load_paired_token`] own the per-user
//!   store, which lives in the invoking user's own state dir and is `0600` on Unix.
//! * [`validate_client_name`] mirrors the server's REFUSAL bound, and [`next_poll_step`] bounds
//!   the approval wait against the server's own `expires_ms`.
//!
//! # Why the ladder is a pure function and not a `cfg!` branch
//!
//! A `cfg!(unix)` branch is only ever exercised on the half of the fleet that compiles it, so the
//! behaviour that matters most on Ubuntu would be untested on the machine most likely to run these
//! tests. More sharply: the unprivileged case CANNOT be reproduced in a test that runs as root,
//! and a unit test cannot drop privileges. Taking both read OUTCOMES as arguments makes the
//! decision assertable on every platform, under any account — the pattern #458 established for
//! [`crate::control`]'s remedy text.
//!
//! # What this does NOT change
//!
//! The paired token is strictly LESS powerful than the master token: `pairing.rs` records that
//! master authorizes pairing administration (`control.pairing.approve` / `.revoke`) and
//! `chiaPeers.add`/`.remove`. A user holding a paired token gains the scoped control surface an
//! operator explicitly approved for them, and nothing else. Nothing here reads, writes, chmods or
//! relocates the master token.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The per-user file holding the scoped token this account was granted.
///
/// It lives beside the invoking user's own node state ([`crate::state::legacy_state_dir`] —
/// `$HOME/DigNode` / `%LOCALAPPDATA%\DigNode`), NOT in the machine-wide state dir: the whole point
/// is that an ordinary user can own it without anyone touching `/var/lib/dig-node`.
pub const PAIRED_CLIENT_TOKEN_FILE: &str = "client-token";

/// The default interval between `pairing.poll` calls while waiting for the operator to approve.
///
/// Short enough that approval feels immediate, long enough that a 5-minute wait is ~100 requests
/// rather than a spin. The wait is bounded by the SERVER's `expires_ms`, never by a local count.
pub const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Where THIS user's paired token lives.
pub fn paired_token_path() -> PathBuf {
    paired_token_path_in(&crate::state::legacy_state_dir())
}

/// [`paired_token_path`] for an explicit directory, so tests use a temp dir and never touch a
/// real one.
pub fn paired_token_path_in(dir: &Path) -> PathBuf {
    dir.join(PAIRED_CLIENT_TOKEN_FILE)
}

/// Read this user's paired token, or `None` when there is not one.
///
/// Every failure is `None`: an absent, blank, or unreadable store means "this account has no
/// paired token", which is exactly the ladder's second rung failing. It is NEVER an error in its
/// own right, because the master read's remedy is the message the user needs.
pub fn load_paired_token(path: &Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Persist a freshly-approved token for this user, owner-only.
///
/// Creates the per-user state dir when absent and applies [`crate::state::restrict_file`] —
/// `0600` on Unix. The file is created by the INVOKING user, so it is owned by them; this
/// function never runs elevated and never touches a machine-wide path.
pub fn store_paired_token(path: &Path, token: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, token)?;
    crate::state::restrict_file(path);
    Ok(())
}

/// The token LADDER, as a pure function over the two read OUTCOMES.
///
/// 1. the master control token when this account can read it (the pre-#403 behaviour, unchanged);
/// 2. else this user's paired token;
/// 3. else the master read's own error, VERBATIM — its remedy text is platform-correct and names
///    the pairing flow (#458), so degrading it would replace the one message that tells the user
///    what to do next.
///
/// `paired` is a THUNK rather than a value so that rung 1 provably never consults the store: with
/// an `Option` argument the caller has already read the file before the decision is made, and no
/// test could tell a correct implementation from one that reads it every time.
pub fn select_token<F>(master: io::Result<String>, paired: F) -> io::Result<String>
where
    F: FnOnce() -> Option<String>,
{
    match master {
        Ok(token) => Ok(token),
        Err(master_err) => match paired() {
            Some(token) => Ok(token),
            None => Err(master_err),
        },
    }
}

/// Validate a `client_name` against the server's bound BEFORE spending a round trip.
///
/// The bound is `pairing::MAX_CLIENT_NAME` itself, so the client cannot drift from the server, and
/// an over-long name is REFUSED rather than shortened — a name this program shortened is a name
/// this program partly wrote, which is precisely the forgery `pairing.rs` refuses to perform.
pub fn validate_client_name(name: &str) -> io::Result<&str> {
    let max = crate::pairing::MAX_CLIENT_NAME;
    if name.chars().count() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "--client-name must be at most {max} characters; this name is refused rather \
                 than shortened, because a name shortened here is a name you did not write and \
                 the operator approves what they see"
            ),
        ));
    }
    Ok(name)
}

/// A sensible default label for this client, always within the bound.
///
/// Names the program and the account, because that is what the operator needs in order to decide
/// whether to approve. If the account name is long enough to blow the budget we fall back to the
/// bare program name rather than clipping — the same refusal-not-truncation rule, applied to a
/// value we chose ourselves.
pub fn default_client_name() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let candidate = if user.trim().is_empty() {
        "dign CLI".to_string()
    } else {
        format!("dign CLI ({})", user.trim())
    };
    if candidate.chars().count() > crate::pairing::MAX_CLIENT_NAME {
        "dign CLI".to_string()
    } else {
        candidate
    }
}

/// What the poll loop should do next, given the clock and the server's own deadline.
#[derive(Debug, PartialEq, Eq)]
pub enum PollStep {
    /// Sleep this long, then poll again.
    Wait(Duration),
    /// The server's `expires_ms` has passed — stop, and tell the user to start over.
    Expired,
}

/// Bound the approval wait by the SERVER's deadline, not by a local retry count.
///
/// `expires_ms` comes from `pairing.request` and is the same value the node's own TTL sweep uses,
/// so the client stops asking at exactly the moment the node stops answering. The final wait is
/// clamped to the remaining time so the loop can never sleep past the deadline and then report a
/// stale state.
pub fn next_poll_step(now_ms: u64, expires_ms: u64, interval: Duration) -> PollStep {
    if now_ms >= expires_ms {
        return PollStep::Expired;
    }
    let remaining = Duration::from_millis(expires_ms - now_ms);
    PollStep::Wait(interval.min(remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the node's control token exists but is NOT readable by your account — \
             `sudo dign pair approve <pairing_id>`",
        )
    }

    /// **Proves (dig-node#403):** an unprivileged account whose master-token read was DENIED
    /// reaches the control plane with its paired token.
    ///
    /// This is the decision the whole ticket is about, and it cannot be exercised any other way:
    /// the test process here runs with whatever privilege CI grants it, a root run cannot observe
    /// the denial, and a unit test cannot drop privileges. Passing the master read's OUTCOME in is
    /// what makes the unprivileged case reachable from a privileged process.
    #[test]
    fn a_denied_master_read_falls_back_to_the_paired_token() {
        let chosen = select_token(Err(denied()), || Some("paired-token".into()))
            .expect("the paired token is the second rung");
        assert_eq!(chosen, "paired-token");
    }

    /// **Proves:** with no paired token, the master read's rich remedy survives INTACT.
    ///
    /// The remedy text landed in #458 and is the only thing that tells the user how to get
    /// unstuck. Both the KIND and the message are asserted, because the CLI maps the kind to its
    /// exit code — a ladder that replaced the error with a generic one would still "fail", and a
    /// test asserting only `is_err()` would not see the regression.
    #[test]
    fn with_no_paired_token_the_master_remedy_is_returned_unchanged() {
        let original = denied();
        let kind = original.kind();
        let text = original.to_string();

        let err = select_token(Err(original), || None).expect_err("no rung can succeed");

        assert_eq!(err.kind(), kind, "the exit-code-bearing kind must survive");
        assert_eq!(err.to_string(), text, "the remedy must not be degraded");
    }

    /// **Proves:** a readable master token wins AND the paired store is never even consulted.
    ///
    /// The second half is the load-bearing half. A ladder that reads the paired file on every
    /// call would satisfy "master wins" identically, so the observable that distinguishes them is
    /// whether the thunk RAN — which is why the parameter is a thunk and not an `Option`.
    #[test]
    fn a_readable_master_token_wins_without_consulting_the_paired_store() {
        let consulted = Cell::new(false);
        let chosen = select_token(Ok("master-token".into()), || {
            consulted.set(true);
            Some("paired-token".into())
        })
        .expect("the master token is the first rung");

        assert_eq!(chosen, "master-token");
        assert!(
            !consulted.get(),
            "rung 1 must not read the per-user store at all"
        );
    }

    /// **Proves:** the per-user store round-trips, and is created owner-only on Unix.
    ///
    /// The mode assertion is one-sided on purpose: `0600` exactly, not "no world bit", because a
    /// group-readable store would be a quieter version of the very widening this ticket refuses to
    /// perform.
    #[test]
    fn the_per_user_store_round_trips_and_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = paired_token_path_in(dir.path());

        assert_eq!(load_paired_token(&path), None, "absent store reads as None");

        store_paired_token(&path, "scoped-token").unwrap();
        assert_eq!(load_paired_token(&path).as_deref(), Some("scoped-token"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the paired store must be owner-only");
        }
    }

    /// **Proves:** a blank store is not a token — it reads as "this account has no paired token"
    /// so the ladder falls through to the master remedy instead of presenting an empty header.
    #[test]
    fn a_blank_store_is_not_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = paired_token_path_in(dir.path());
        std::fs::write(&path, "   \n").unwrap();
        assert_eq!(load_paired_token(&path), None);
    }

    /// **Proves:** an over-long `--client-name` is REFUSED, not truncated.
    ///
    /// Pinned from BOTH sides: exactly at the bound must pass, one character over must fail. A
    /// bound tested only from below can only confirm itself, and the failing side is the one that
    /// matters — a client that clipped locally would send a short, trusted-looking name for the
    /// operator to approve.
    #[test]
    fn an_over_long_client_name_is_refused_not_truncated() {
        let at_bound = "n".repeat(crate::pairing::MAX_CLIENT_NAME);
        assert_eq!(
            validate_client_name(&at_bound).unwrap(),
            at_bound,
            "a name AT the bound is accepted verbatim"
        );

        let too_long = "n".repeat(crate::pairing::MAX_CLIENT_NAME + 1);
        let err = validate_client_name(&too_long).expect_err("one over the bound is refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            !err.to_string().contains(&"n".repeat(8)),
            "the refusal must not echo a shortened form of the name back as if it were usable"
        );
    }

    /// **Proves:** the default label never trips the bound the client just promised to respect.
    #[test]
    fn the_default_client_name_is_within_the_bound() {
        let name = default_client_name();
        assert!(validate_client_name(&name).is_ok(), "default was {name:?}");
        assert!(!name.is_empty());
    }

    /// **Proves:** polling TERMINATES on the server's deadline rather than spinning.
    ///
    /// Time is pinned explicitly rather than read from the wall clock — a fixture that passed a
    /// small literal through a real-clock API would be ~1.8 billion seconds expired and would
    /// exercise only the expiry arm while claiming to test both.
    #[test]
    fn polling_waits_until_the_servers_deadline_and_then_stops() {
        const NOW: u64 = 1_700_000_000_000;
        let interval = Duration::from_secs(3);

        assert_eq!(
            next_poll_step(NOW, NOW + 60_000, interval),
            PollStep::Wait(interval),
            "well inside the window, poll at the ordinary interval"
        );
        assert_eq!(
            next_poll_step(NOW, NOW + 1_000, interval),
            PollStep::Wait(Duration::from_millis(1_000)),
            "the last wait is clamped so the loop cannot sleep PAST the deadline"
        );
        assert_eq!(
            next_poll_step(NOW, NOW, interval),
            PollStep::Expired,
            "at the deadline the node has already stopped answering"
        );
        assert_eq!(
            next_poll_step(NOW + 1, NOW, interval),
            PollStep::Expired,
            "past the deadline, stop"
        );
    }
}
