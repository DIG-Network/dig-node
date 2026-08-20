//! Bring-up + observable state of the Sage-parity wallet mTLS listener (#368, dig-node#260).
//!
//! The listener is BEST-EFFORT: the wallet is also served on the loopback plain-HTTP
//! surface (`POST /{method}`) and `/ws`, so a busy port must not stop the node. It used to
//! be best-effort AND SILENT, which is the half of dig-node#260 that cost a user their
//! afternoon: whichever process lost the race for the socket lost it with no error on
//! either side, so the contention was undiagnosable from the machine it happened on.
//!
//! So the bind outcome is recorded here and published on `control.status` (`dign info`).
//! An operator who cannot reach the parity port can now see, in one command, that the
//! listener never came up and which port it wanted.

use std::net::TcpListener;
use std::sync::{Arc, RwLock};

use serde_json::{json, Value};

use dig_wallet::sage::rpc::WalletBackend;
use dig_wallet::sage::transport::{serve_mtls, SharedCert};

/// What the last bring-up attempt did. `NotStarted` is the pre-serve state — a node that
/// never reached the serve path (the in-process browser runtime, a CLI subcommand).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerState {
    /// The serve path has not attempted the bind yet.
    NotStarted,
    /// Bound and serving on this loopback port.
    Listening(u16),
    /// The bind failed — almost always another process already holds the port.
    Unavailable {
        /// The port that was attempted.
        port: u16,
        /// The OS error, verbatim, because "address in use" is the whole diagnosis.
        reason: String,
    },
}

impl ListenerState {
    /// The `control.status` projection: an operator-readable object, stable field names.
    fn to_json(&self) -> Value {
        match self {
            Self::NotStarted => json!({ "state": "not_started" }),
            Self::Listening(port) => json!({ "state": "listening", "port": port }),
            Self::Unavailable { port, reason } => json!({
                "state": "unavailable",
                "port": port,
                "reason": reason,
                "detail": "another process holds this port; the wallet is still served on \
                           the loopback HTTP surface and /ws",
            }),
        }
    }
}

/// Process-global because the reader (`control.status`) and the writer (the serve path)
/// share no value: the listener is spawned before the control context exists.
static STATE: RwLock<ListenerState> = RwLock::new(ListenerState::NotStarted);

/// The current listener state, for `control.status`.
pub fn status_json() -> Value {
    read_state().to_json()
}

/// The current listener state.
pub fn state() -> ListenerState {
    read_state()
}

fn read_state() -> ListenerState {
    // A poisoned lock still holds a valid state: a panic in this module cannot leave a
    // half-written enum. Reporting the state beats making a status read panic.
    match STATE.read() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    }
}

fn set_state(next: ListenerState) {
    match STATE.write() {
        Ok(mut g) => *g = next,
        Err(p) => *p.into_inner() = next,
    }
}

/// Bind the wallet mTLS listener on loopback and spawn it, recording the outcome.
///
/// Never fatal: a failure is logged at WARN and published on `control.status` so the
/// operator learns about the contention from the node itself rather than from an opaque
/// TLS `handshake_failure` in whatever else wanted the port.
pub fn spawn(port: u16, backend: Arc<WalletBackend>, cert: SharedCert) {
    let Some(listener) = bind_and_record(port) else {
        return;
    };
    tokio::spawn(async move {
        if let Err(e) = serve_mtls(backend, listener, &cert).await {
            tracing::warn!(error = %e, "wallet mTLS listener exited");
        }
    });
}

/// Take the loopback port, recording + logging the outcome either way.
///
/// Split out of [`spawn`] so the outcome-recording — the part dig-node#260 was about —
/// is reachable by a test without a live wallet backend and a TLS cert.
fn bind_and_record(port: u16) -> Option<TcpListener> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            let _ = listener.set_nonblocking(true);
            set_state(ListenerState::Listening(port));
            tracing::info!(
                addr = %format!("127.0.0.1:{port}"),
                "wallet mTLS (Sage-parity) listening"
            );
            Some(listener)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                addr = %format!("127.0.0.1:{port}"),
                "the wallet mTLS listener could not bind: another process already holds this \
                 port. Node-class Sage-parity clients are unavailable (non-fatal) — the wallet \
                 is still served on the loopback HTTP surface and /ws. `dign info` reports this."
            );
            set_state(ListenerState::Unavailable {
                port,
                reason: e.to_string(),
            });
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A LOST bind must be visible, and a WON bind must say which port it holds.
    ///
    /// Both halves live in one test because the state is process-global: split across two
    /// `#[test]` fns the harness could interleave them and each would observe the other's
    /// write. The occupied port is a real one held by a live listener for the duration —
    /// a made-up busy port would prove nothing about the bind path.
    #[test]
    fn a_lost_bind_is_recorded_and_a_won_bind_names_its_port() {
        assert_eq!(state(), ListenerState::NotStarted, "clean process state");

        let squatter = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral bind");
        let taken = squatter.local_addr().unwrap().port();

        assert!(
            bind_and_record(taken).is_none(),
            "a held port cannot be bound"
        );

        match state() {
            ListenerState::Unavailable { port, reason } => {
                assert_eq!(port, taken);
                assert!(!reason.is_empty(), "the OS error is the diagnosis");
            }
            other => panic!("a lost bind must be recorded, got {other:?}"),
        }
        let json = status_json();
        assert_eq!(json["state"], "unavailable");
        assert_eq!(json["port"], taken);

        // Now a port nothing holds: the squatter's, released. The control proves the
        // `unavailable` verdict above came from the contention and not from the recorder
        // reporting failure unconditionally.
        drop(squatter);
        let held = bind_and_record(taken).expect("a free port binds");
        assert_eq!(state(), ListenerState::Listening(taken));
        assert_eq!(status_json()["port"], taken);
        drop(held);
    }
}
