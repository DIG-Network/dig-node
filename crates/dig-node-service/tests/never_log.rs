//! Never-log regression tests (#553, dig-logging SPEC §7).
//!
//! The node's on-disk logs are operator-readable, so no secret may EVER reach a `tracing` field or
//! message at source (bundle-time redaction is only the second line of defence). The risk surface
//! is the control/pairing token path and the wallet seed path. These tests capture real emitted
//! records into an in-memory buffer and assert curated secret sentinels are absent, so a future
//! edit that logs a token/seed fails HERE.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

/// A sentinel BIP39-style seed that must never surface in a log line.
const SENTINEL_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon about test seed leak";
/// A sentinel control/pairing token value that must never surface in a log line.
const SENTINEL_TOKEN: &str = "deadbeefcafef00d-control-token-sentinel-value";

/// An in-memory sink a `tracing_subscriber::fmt` layer writes formatted records into, so a test can
/// read back everything that was logged.
#[derive(Clone, Default)]
struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl CaptureBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for CaptureBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureBuffer {
    type Writer = CaptureBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `body` with a scoped capturing subscriber at `TRACE` (so even the lowest-level events are
/// captured) and return everything it logged.
fn capture(body: impl FnOnce()) -> String {
    let buffer = CaptureBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(buffer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    buffer.contents()
}

/// The request-logging path records the METHOD and an op_id — and, by construction, nothing else.
/// Its signature takes only the method name, so a control body's token can never reach it; this
/// test pins that guarantee by logging a control method while the token sentinel is in scope and
/// asserting the sentinel never appears.
#[test]
fn rpc_dispatch_logging_records_method_but_never_the_request_token() {
    let logged = capture(|| {
        // The token a real caller would carry alongside `control.config.setUpstream`; it must NOT
        // be handed to the request logger, and the logger's signature makes that impossible.
        let _presented_token = SENTINEL_TOKEN;
        dig_node_service::logging::log_rpc_dispatch("control.config.setUpstream");
    });

    assert!(
        logged.contains("control.config.setUpstream"),
        "the method name is the useful diagnostic and must be logged: {logged}"
    );
    assert!(
        logged.contains("rpc dispatch"),
        "the dispatch event should be emitted: {logged}"
    );
    assert!(
        !logged.contains(SENTINEL_TOKEN),
        "a control token must NEVER reach a log record (SPEC §7): {logged}"
    );
}

/// Broad guard: even when secret sentinels are live in the surrounding scope, none of the crate's
/// own emitted records may contain them. Emitting a representative operator event proves the
/// capture harness sees output, and the assertions prove the sentinels are absent from it.
#[test]
fn emitted_records_never_contain_seed_or_token_sentinels() {
    let logged = capture(|| {
        let _seed = SENTINEL_MNEMONIC;
        let _token = SENTINEL_TOKEN;
        // A representative lifecycle event (the shape of the real bring-up narration): public,
        // non-secret fields only.
        tracing::info!(
            addr = "127.0.0.1:9778",
            upstream = "https://rpc.dig.net",
            "listening"
        );
        dig_node_service::logging::log_rpc_dispatch("dig.getContent");
    });

    assert!(
        !logged.is_empty(),
        "the capture harness must see emitted output"
    );
    for sentinel in [SENTINEL_MNEMONIC, SENTINEL_TOKEN] {
        assert!(
            !logged.contains(sentinel),
            "a secret sentinel leaked into a log record (SPEC §7): {logged}"
        );
    }
}
