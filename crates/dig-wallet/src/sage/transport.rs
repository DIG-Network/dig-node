//! The dual transport (design **C.3**): ONE method surface, TWO transports.
//!
//! Both listeners dispatch the **same** [`WalletBackend`] handler set
//! ([`WalletBackend::dispatch`]), so their JSON bodies are byte-identical by construction
//! — only the TLS envelope differs:
//!
//! 1. **mTLS [`DEFAULT_MTLS_PORT`]** — Sage byte-parity ([`serve_mtls`]). `POST /{method}` over TLS with
//!    Sage's shared-self-signed-cert **mutual-TLS** model ([`SharedCertVerifier`]): the
//!    server accepts a client cert iff its DER is byte-identical to the server's own cert
//!    (design A.2). A drop-in for a Sage RPC client.
//! 2. **Plain-HTTP + CORS** — the browser mirror ([`serve_http`]). Because a browser/MV3
//!    extension cannot present a client cert (design A.2/D.4), the identical surface is
//!    also served over the loopback plain-HTTP transport with permissive CORS.
//!
//! Both bind loopback only. `build_router` produces the shared `Router`; the HTTP mirror
//! layers CORS on top of the same routes.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        Response,
    },
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use futures_core::Stream;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tower_http::cors::{Any, CorsLayer};

use super::events::SyncEvent;
use super::rpc::WalletBackend;

/// The header a node-class client presents its control/paired token in, byte-identical to the
/// control plane's `X-Dig-Control-Token`.
///
/// It is declared HERE, in the crate that owns the transport, because the transport is what must
/// read it; `dig-node-service` asserts the two spellings agree rather than each guessing.
pub const WALLET_TOKEN_HEADER: &str = "x-dig-control-token";

/// The authorization decision every route into [`WalletBackend::dispatch`] MUST obtain first.
///
/// # Why this is a constructor parameter rather than a middleware someone remembers to add
///
/// The Sage-parity mTLS listener used to authenticate with [`SharedCertVerifier`] alone and then
/// dispatch the entire wallet surface — custody, spends and master-tier peer mutations — on
/// possession of the shared cert (dig-node#257). The two token-bearing planes in
/// `dig-node-service` were gated; this third one was not, because nothing in the type system
/// asked it to be. A per-route test could not see the hole either, since the hole was a route
/// nobody had written a test for.
///
/// [`build_router`] therefore takes a gate and there is exactly ONE handler behind `POST
/// /{method}`, so a fourth transport cannot reach `dispatch` without answering this question. The
/// POLICY still lives in `dig-node-service` (`wallet_authz`), which is the only place that knows
/// the tier of a capability; this crate owns only the obligation to ask.
pub trait WalletCallGate: Send + Sync + 'static {
    /// Whether `method` may run for a caller presenting `presented`.
    ///
    /// `presented` is the raw token from [`WALLET_TOKEN_HEADER`], or `None` when the caller sent
    /// no token at all. An implementation MUST treat `None` as unauthenticated rather than as a
    /// local-possession grant — reaching the loopback socket is not a capability tier.
    fn authorize(&self, method: &str, presented: Option<&str>) -> bool;
}

/// A gate that authorizes NOTHING.
///
/// This is the correct default for a transport whose policy owner has not been wired yet: a node
/// that cannot decide serves no wallet method. It exists so "no gate available" is expressible as
/// a refusal instead of as an omission.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl WalletCallGate for DenyAll {
    fn authorize(&self, _method: &str, _presented: Option<&str>) -> bool {
        false
    }
}

/// The shared axum state: the handler set plus the gate that guards it.
#[derive(Clone)]
struct TransportState {
    backend: Arc<WalletBackend>,
    gate: Arc<dyn WalletCallGate>,
}

/// The default loopback port for the Sage-parity wallet mTLS listener (design C.4).
///
/// **This is deliberately NOT Sage's own RPC port.** Sage defaults its RPC to `9257`
/// (`sage-config`'s `RpcConfig::default`), and dig-node binding it made an
/// auto-starting OS service race a desktop wallet for the same socket: whichever
/// started first won, and a Sage client that reached OUR listener was rejected by the
/// mutual-TLS handshake, surfacing as an opaque `handshake_failure` far from its cause
/// (dig-node#260). The parity here is of the METHOD SURFACE, never of the port.
///
/// `9776` sits with the rest of the DIG cluster (`9777` wallet HTTP mirror, `9778`
/// control RPC, `9779` dig-app identity), so the number reads as ours on sight.
pub const DEFAULT_MTLS_PORT: u16 = 9776;

/// Sage's own default RPC port, which this node MUST NEVER bind (dig-node#260).
///
/// Recorded as a named constant so the prohibition is testable rather than folklore:
/// see the `default_mtls_port_is_not_sages_rpc_port` test below.
pub const SAGE_RPC_PORT: u16 = 9257;

/// The shared self-signed certificate that is BOTH the server cert AND the only accepted
/// client cert (design A.2). Whoever can read the cert+key is authorized — a
/// local-possession model, byte-parity with Sage.
#[derive(Clone)]
pub struct SharedCert {
    /// The certificate DER.
    pub cert_der: Vec<u8>,
    /// The PKCS#8 private-key DER.
    pub key_pkcs8_der: Vec<u8>,
    /// The certificate PEM.
    pub cert_pem: String,
    /// The private-key PEM.
    pub key_pem: String,
}

impl SharedCert {
    /// Generate a fresh self-signed cert/key (mirrors Sage shipping a cert in its data
    /// dir; a real deployment persists this so a client can read it).
    pub fn generate() -> Result<Self, rcgen::Error> {
        let ck = rcgen::generate_simple_self_signed(vec!["dig-wallet".to_string()])?;
        Ok(Self {
            cert_der: ck.cert.der().as_ref().to_vec(),
            key_pkcs8_der: ck.key_pair.serialize_der(),
            cert_pem: ck.cert.pem(),
            key_pem: ck.key_pair.serialize_pem(),
        })
    }

    /// The concatenated cert+key PEM a Sage-style client loads as its `reqwest::Identity`
    /// (design A.2 client side).
    pub fn client_identity_pem(&self) -> String {
        format!("{}{}", self.cert_pem, self.key_pem)
    }
}

/// Sage's shared-cert mutual-TLS verifier: accept a client cert iff its DER equals the
/// server's own cert DER (design A.2 `WalletCertVerifier`).
#[derive(Debug)]
pub struct SharedCertVerifier {
    cert_der: Vec<u8>,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for SharedCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if end_entity.as_ref() == self.cert_der.as_slice() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "client cert is not the shared wallet cert".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Build the rustls `ServerConfig` for the mTLS listener with the shared-cert verifier.
pub fn build_server_config(cert: &SharedCert) -> Result<rustls::ServerConfig, RustlsError> {
    let provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(SharedCertVerifier {
        cert_der: cert.cert_der.clone(),
        algs,
    });
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pkcs8_der.clone()));
    rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| RustlsError::General(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(cert.cert_der.clone())], key)
}

/// The axum handler for `POST /{method}` — AUTHORIZE, then read the body, run
/// [`WalletBackend::dispatch`], and reproduce Sage's response model: `200` + JSON on success, the
/// mapped status + a plain-text message on error (design A.1/A.3).
///
/// The gate runs BEFORE the body is even interpreted, so a refused call cannot reach a handler,
/// touch the db, or spend. A refusal is `401` + plain text, distinct from Sage's `404` for an
/// unsupported method: a caller must be able to tell "you may not" from "there is no such thing".
async fn handle(
    State(state): State<TransportState>,
    Path(method): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let presented = headers
        .get(WALLET_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok());
    if !state.gate.authorize(&method, presented) {
        return plain_response(
            StatusCode::UNAUTHORIZED,
            "this wallet method requires the local control token (X-Dig-Control-Token) or a \
             paired controller token (see `dig-node pair`); presenting the shared wallet \
             certificate authenticates the transport, it does not authorize the capability"
                .to_string(),
        );
    }
    let body_str = String::from_utf8_lossy(&body);
    let (status, out) = state.backend.dispatch(&method, &body_str).await;
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status == 200 {
        let mut resp = Response::new(axum::body::Body::from(out));
        *resp.status_mut() = code;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    } else {
        plain_response(code, out)
    }
}

/// A `text/plain` response with `code` — Sage's error shape, and the shape a refusal takes.
fn plain_response(code: StatusCode, body: String) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = code;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// The `SyncEvent` type tag (design A.9) an event maps to, used as the SSE `event:` name.
fn event_type_tag(event: &SyncEvent) -> &'static str {
    match event {
        SyncEvent::Start { .. } => "start",
        SyncEvent::Stop => "stop",
        SyncEvent::Subscribed => "subscribed",
        SyncEvent::Derivation => "derivation",
        SyncEvent::CoinState => "coin_state",
        SyncEvent::TransactionFailed { .. } => "transaction_failed",
        SyncEvent::PuzzleBatchSynced => "puzzle_batch_synced",
        SyncEvent::CatInfo => "cat_info",
        SyncEvent::DidInfo => "did_info",
        SyncEvent::NftData => "nft_data",
    }
}

/// The `GET /events` SSE handler (design A.9, #205 PR4): subscribes to the backend's
/// [`super::events::EventBus`] and streams every published [`SyncEvent`] as a
/// Server-Sent Event (the `event:` field is the Sage `type` tag; `data:` is the event's full
/// JSON, byte-parity with the wire shape `dispatch` would use if this were a poll). A lagging
/// subscriber (missed events dropped from the broadcast channel) simply skips the gap rather
/// than erroring the stream — `get_sync_status` polling remains the authoritative source of
/// truth regardless.
///
/// `GET /events` does NOT reach [`WalletBackend::dispatch`] and carries no method name, so the
/// per-method gate has nothing to answer about it; it streams the same sync notifications the
/// open read plane already publishes.
async fn handle_events(
    State(state): State<TransportState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.backend.events().subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| {
        let event = item.ok()?;
        let tag = event_type_tag(&event);
        let sse_event = Event::default()
            .event(tag)
            .json_data(&event)
            .unwrap_or_else(|_| Event::default().event(tag));
        Some(Ok(sse_event))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Build the shared `Router` (`POST /{method}` + `GET /events`) both transports dispatch.
///
/// `gate` is REQUIRED: there is no router without an authorization policy (dig-node#257).
pub fn build_router(backend: Arc<WalletBackend>, gate: Arc<dyn WalletCallGate>) -> Router {
    Router::new()
        .route("/:method", post(handle))
        .route("/events", get(handle_events))
        .with_state(TransportState { backend, gate })
}

/// The browser mirror's router: the shared routes + permissive CORS (loopback only, so a
/// wildcard origin is safe; the extension origin is `chrome-extension://…`).
///
/// CORS widens who may SPEAK to the surface; it does not widen what they may do. The same gate
/// applies, which is why a browser client must present the same token a node-class client does.
pub fn build_cors_router(backend: Arc<WalletBackend>, gate: Arc<dyn WalletCallGate>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_headers(Any);
    build_router(backend, gate).layer(cors)
}

/// Serve the wallet mTLS listener (Sage byte-parity) on a pre-bound std listener.
pub async fn serve_mtls(
    backend: Arc<WalletBackend>,
    listener: std::net::TcpListener,
    cert: &SharedCert,
    gate: Arc<dyn WalletCallGate>,
) -> std::io::Result<()> {
    let config = build_server_config(cert).map_err(|e| std::io::Error::other(e.to_string()))?;
    let rustls_config = RustlsConfig::from_config(Arc::new(config));
    axum_server::from_tcp_rustls(listener, rustls_config)
        .serve(build_router(backend, gate).into_make_service())
        .await
}

/// Serve the plain-HTTP + CORS browser mirror on a pre-bound tokio listener.
pub async fn serve_http(
    backend: Arc<WalletBackend>,
    listener: tokio::net::TcpListener,
    gate: Arc<dyn WalletCallGate>,
) -> std::io::Result<()> {
    axum::serve(listener, build_cors_router(backend, gate)).await
}

/// Bring up BOTH transports on loopback (design C.3): the wallet mTLS listener and the
/// plain-HTTP+CORS browser mirror, each dispatching the shared handler set behind the SAME gate.
/// Returns once either listener exits. Both bind `127.0.0.1` only.
pub async fn serve_dual(
    backend: Arc<WalletBackend>,
    mtls_port: u16,
    http_port: u16,
    cert: SharedCert,
    gate: Arc<dyn WalletCallGate>,
) -> std::io::Result<()> {
    let mtls_listener = std::net::TcpListener::bind(("127.0.0.1", mtls_port))?;
    let http_listener = tokio::net::TcpListener::bind(("127.0.0.1", http_port)).await?;
    let mtls = {
        let backend = backend.clone();
        let gate = gate.clone();
        tokio::spawn(async move { serve_mtls(backend, mtls_listener, &cert, gate).await })
    };
    let http = tokio::spawn(async move { serve_http(backend, http_listener, gate).await });
    tokio::select! {
        r = mtls => r.map_err(|e| std::io::Error::other(e.to_string()))?,
        r = http => r.map_err(|e| std::io::Error::other(e.to_string()))?,
    }
}

#[cfg(test)]
mod tests {
    use super::super::fallback::mock::MockFallback;
    use super::super::rpc::WalletConfig;
    use super::*;
    use crate::sage::db::WalletDb;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// The listener must never sit on a port another wallet or a Chia service owns.
    ///
    /// The whole of dig-node#260 was one number in this file, so the prohibition is
    /// pinned here rather than left to review: `9257` is Sage's RPC (confirmed against
    /// `sage-config`'s `RpcConfig::default`), and the rest are Chia's published binds.
    /// A future "just use the parity port" edit fails this test instead of a user's wallet.
    #[test]
    fn default_mtls_port_is_not_sages_rpc_port() {
        /// Ports owned by software a DIG user is likely to run alongside the node:
        /// Sage's RPC, then Chia's full node, node RPC, wallet RPC, harvester, farmer,
        /// daemon, introducer, and the testnet variants.
        const RESERVED: &[u16] = &[
            SAGE_RPC_PORT,
            8444,
            8555,
            8447,
            8446,
            8559,
            8560,
            9256,
            55400,
            18444,
            58444,
        ];
        assert_eq!(SAGE_RPC_PORT, 9257, "Sage's RPC port is 9257");
        assert!(
            !RESERVED.contains(&DEFAULT_MTLS_PORT),
            "DEFAULT_MTLS_PORT {DEFAULT_MTLS_PORT} is bound by another wallet or Chia service; pick one outside {RESERVED:?}"
        );
    }

    /// A test gate that authorizes everything, so the pre-existing transport tests keep
    /// exercising the dispatch path they were written for.
    ///
    /// It is deliberately test-only: the production crate offers [`DenyAll`] and nothing else, so
    /// an allow-everything policy cannot be reached by a shipping call site.
    struct AllowAll;
    impl WalletCallGate for AllowAll {
        fn authorize(&self, _method: &str, _presented: Option<&str>) -> bool {
            true
        }
    }

    fn allow_all() -> Arc<dyn WalletCallGate> {
        Arc::new(AllowAll)
    }

    /// One question the gate was asked: the method name, and the token presented with it.
    type GateQuestion = (String, Option<String>);

    /// The shared log of every question a [`RecordingGate`] answered.
    type GateLog = Arc<std::sync::Mutex<Vec<GateQuestion>>>;

    /// A gate that records every question it was asked and answers with a fixed verdict.
    #[derive(Clone)]
    struct RecordingGate {
        verdict: bool,
        asked: GateLog,
    }

    impl RecordingGate {
        fn new(verdict: bool) -> Self {
            Self {
                verdict,
                asked: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn asked_methods(&self) -> Vec<String> {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .map(|(m, _)| m.clone())
                .collect()
        }
    }

    impl WalletCallGate for RecordingGate {
        fn authorize(&self, method: &str, presented: Option<&str>) -> bool {
            self.asked
                .lock()
                .unwrap()
                .push((method.to_string(), presented.map(str::to_string)));
            self.verdict
        }
    }

    async fn test_backend() -> Arc<WalletBackend> {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
        Arc::new(WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        ))
    }

    async fn oneshot_body(router: Router, method: &str) -> (u16, String) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{method}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn both_transport_routers_return_byte_identical_bodies() {
        let backend = test_backend().await;
        // The two transports differ only by the CORS layer; the dispatched body must be
        // byte-identical (acceptance #3, structural proof).
        let base = build_router(backend.clone(), allow_all());
        let cors = build_cors_router(backend.clone(), allow_all());
        let (s1, b1) = oneshot_body(base, "get_version").await;
        let (s2, b2) = oneshot_body(cors, "get_version").await;
        let direct = backend.dispatch("get_version", "{}").await;
        assert_eq!(s1, 200);
        assert_eq!((s1, &b1), (s2, &b2));
        assert_eq!(b1, direct.1);
    }

    #[tokio::test]
    async fn error_body_is_plain_text_with_mapped_status() {
        let backend = test_backend().await;
        let (status, body) =
            oneshot_body(build_router(backend, allow_all()), "get_secret_key").await;
        assert_eq!(status, 404);
        assert!(body.contains("unsupported"));
    }

    #[test]
    fn shared_cert_verifier_accepts_matching_rejects_other() {
        let provider = rustls::crypto::ring::default_provider();
        let algs = provider.signature_verification_algorithms;
        let cert_der = vec![1u8, 2, 3, 4];
        let verifier = SharedCertVerifier {
            cert_der: cert_der.clone(),
            algs,
        };
        let now = UnixTime::now();

        let ours = CertificateDer::from(cert_der);
        assert!(verifier.verify_client_cert(&ours, &[], now).is_ok());

        let other = CertificateDer::from(vec![9u8, 9, 9]);
        assert!(verifier.verify_client_cert(&other, &[], now).is_err());
    }

    #[test]
    fn mtls_server_config_builds_from_shared_cert() {
        // The wallet mTLS listener's rustls config (shared-cert client-auth verifier + server
        // cert) is constructible from a generated shared cert.
        let cert = SharedCert::generate().unwrap();
        assert!(build_server_config(&cert).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_mirror_serves_get_version_over_the_wire() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A real end-to-end round-trip over the browser-facing transport (the one the
        // extension uses in phase 3): bind the CORS mirror, speak raw HTTP/1.1 over a
        // socket, and assert the body equals the transport-independent dispatch (so the
        // wire path returns exactly what `dispatch` produces — acceptance #3, over the
        // wire, without pulling a heavy TLS client into the dev graph).
        let backend = test_backend().await;
        let expected = backend.dispatch("get_version", "{}").await.1;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_http(backend, listener, allow_all()));

        // Retry-connect so the test never races the server's first accept.
        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut stream = stream.expect("connect to http mirror");

        let req = "POST /get_version HTTP/1.1\r\nHost: localhost\r\nContent-Type: \
                   application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");

        assert!(
            text.starts_with("HTTP/1.1 200"),
            "expected 200, got: {text}"
        );
        assert_eq!(body, expected, "wire body must equal dispatch output");
        assert!(body.contains(env!("CARGO_PKG_VERSION")));
    }

    /// **Proves:** `GET /events` (design A.9) subscribes to the backend's event bus and
    /// streams a published [`SyncEvent`] as a Server-Sent Event — the `event:` field is the
    /// Sage `type` tag and `data:` carries the event's JSON.
    #[tokio::test]
    async fn events_sse_streams_a_published_sync_event() {
        let backend = test_backend().await;
        let router = build_cors_router(backend.clone(), allow_all());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/events")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The handler has already subscribed by the time the response is ready (subscribing
        // happens synchronously while building the stream, before any bytes are polled).
        backend.events().publish(SyncEvent::Stop);

        let mut body = resp.into_body();
        let mut collected = Vec::new();
        let found = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            collected.extend_from_slice(data);
                            if String::from_utf8_lossy(&collected).contains("event: stop") {
                                return true;
                            }
                        }
                    }
                    Some(Err(_)) | None => return false,
                }
            }
        })
        .await
        .unwrap_or(false);

        let text = String::from_utf8_lossy(&collected);
        assert!(found, "expected an SSE 'stop' event, got: {text}");
        assert!(text.contains("\"type\":\"stop\""), "got: {text}");
    }

    /// **Proves:** the `/events` route coexists with the `/:method` POST dispatch route on
    /// the SAME router without a construction-time panic or routing conflict — the static
    /// `/events` route takes precedence over the dynamic `/:method` parameter route at the
    /// same path (matching axum's documented static-over-dynamic routing priority), so a
    /// `POST /events` (the SSE route is GET-only) is a `405 Method Not Allowed`, never
    /// silently misrouted into the method dispatcher.
    #[tokio::test]
    async fn events_route_coexists_with_method_dispatch_route() {
        let backend = test_backend().await;
        let (status, _) = oneshot_body(build_router(backend, allow_all()), "events").await;
        assert_eq!(status, 405);
    }

    /// **Proves (dig-node#257):** NO route into [`WalletBackend::dispatch`] runs without the gate
    /// having answered first — for a wallet read, a custody mutation, a master-tier peer
    /// mutation, a retired custody name, and a method name that does not exist at all.
    ///
    /// The unknown name is the load-bearing case. A per-route or per-method-list gate is
    /// satisfied by enumerating the methods someone thought of, which is exactly how the mTLS
    /// plane came to serve the whole surface ungated: the hole was a route nobody had listed.
    /// Asking the gate about a name the backend has never heard of proves the question is asked
    /// by the ROUTER, not by a table.
    #[tokio::test]
    async fn every_route_into_dispatch_consults_the_gate_including_unknown_methods() {
        const PROBES: &[&str] = &[
            "get_version",
            "get_sync_status",
            "send_xch",
            "sign_coin_spends",
            "submit_transaction",
            "add_peer",
            "wallet.unlock",
            "a_method_that_has_never_existed",
        ];

        let backend = test_backend().await;
        let gate = RecordingGate::new(false);
        let router = build_router(backend.clone(), Arc::new(gate.clone()));

        for method in PROBES {
            let (status, body) = oneshot_body(router.clone(), method).await;
            assert_eq!(
                status, 401,
                "`{method}` was served by a denying gate; the transport authorizes on cert \
                 possession alone"
            );
            assert!(
                body.contains("control token"),
                "the refusal must name the credential it wants, got: {body}"
            );
        }

        assert_eq!(
            gate.asked_methods(),
            PROBES.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
            "the gate must be consulted once per call, for every method name"
        );
    }

    /// **Proves:** a denied call never reaches the handler set — the refusal body is not the
    /// dispatch output, so the method did not run and merely had its answer suppressed.
    ///
    /// Asserting the status alone would pass against an implementation that dispatched first and
    /// rewrote the status afterwards, which for `submit_transaction` would have already
    /// broadcast.
    #[tokio::test]
    async fn a_denied_call_does_not_reach_dispatch() {
        let backend = test_backend().await;
        let dispatched = backend.dispatch("get_version", "{}").await.1;
        assert!(
            dispatched.contains(env!("CARGO_PKG_VERSION")),
            "control: dispatch really does answer get_version"
        );

        let router = build_router(backend.clone(), Arc::new(DenyAll));
        let (status, body) = oneshot_body(router, "get_version").await;

        assert_eq!(status, 401);
        assert_ne!(
            body, dispatched,
            "the denied call still produced the dispatch body"
        );
    }

    /// **Proves:** the gate receives the token verbatim from [`WALLET_TOKEN_HEADER`], and `None`
    /// when the caller sends nothing — so a policy that distinguishes master from paired from
    /// absent can actually express that distinction on this transport.
    #[tokio::test]
    async fn the_presented_token_reaches_the_gate_verbatim() {
        let backend = test_backend().await;
        let gate = RecordingGate::new(true);
        let router = build_router(backend, Arc::new(gate.clone()));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/get_version")
            .header("content-type", "application/json")
            .header(WALLET_TOKEN_HEADER, "tok-abc")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        router.clone().oneshot(req).await.unwrap();
        let (_, _) = oneshot_body(router, "get_version").await;

        let asked = gate.asked.lock().unwrap().clone();
        assert_eq!(
            asked,
            vec![
                ("get_version".to_string(), Some("tok-abc".to_string())),
                ("get_version".to_string(), None),
            ],
            "the header token must reach the gate unchanged, and its absence must read as None"
        );
    }

    /// **Proves:** [`DenyAll`] is the only policy this crate ships. A transport whose policy
    /// owner has not been wired serves nothing rather than everything.
    #[test]
    fn deny_all_refuses_every_method_with_and_without_a_token() {
        for method in ["get_version", "send_xch", ""] {
            assert!(!DenyAll.authorize(method, None));
            assert!(!DenyAll.authorize(method, Some("any-token")));
        }
    }
}
