//! The dual transport (design **C.3**): ONE method surface, TWO transports.
//!
//! Both listeners dispatch the **same** [`WalletBackend`] handler set
//! ([`WalletBackend::dispatch`]), so their JSON bodies are byte-identical by construction
//! — only the TLS envelope differs:
//!
//! 1. **mTLS `9257`** — Sage byte-parity ([`serve_mtls`]). `POST /{method}` over TLS with
//!    Sage's shared-self-signed-cert **mutual-TLS** model ([`SharedCertVerifier`]): the
//!    server accepts a client cert iff its DER is byte-identical to the server's own cert
//!    (design A.2). A drop-in for a Sage RPC client.
//! 2. **Plain-HTTP + CORS** — the browser mirror ([`serve_http`]). Because a browser/MV3
//!    extension cannot present a client cert (design A.2/D.4), the identical surface is
//!    also served over the loopback plain-HTTP transport with permissive CORS.
//!
//! Both bind loopback only. `build_router` produces the shared `Router`; the HTTP mirror
//! layers CORS on top of the same routes.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::Response,
    routing::post,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use tower_http::cors::{Any, CorsLayer};

use super::rpc::WalletBackend;

/// The Sage-parity RPC default mTLS port (design C.4). Loopback only.
pub const DEFAULT_MTLS_PORT: u16 = 9257;

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

/// The axum handler for `POST /{method}` — read the body, run [`WalletBackend::dispatch`],
/// and reproduce Sage's response model: `200` + JSON on success, the mapped status + a
/// plain-text message on error (design A.1/A.3).
async fn handle(
    State(backend): State<Arc<WalletBackend>>,
    Path(method): Path<String>,
    body: Bytes,
) -> Response {
    let body_str = String::from_utf8_lossy(&body);
    let (status, out) = backend.dispatch(&method, &body_str).await;
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = if status == 200 {
        "application/json"
    } else {
        "text/plain; charset=utf-8"
    };
    let mut resp = Response::new(axum::body::Body::from(out));
    *resp.status_mut() = code;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp
}

/// Build the shared `Router` (`POST /{method}`) both transports dispatch.
pub fn build_router(backend: Arc<WalletBackend>) -> Router {
    Router::new()
        .route("/:method", post(handle))
        .with_state(backend)
}

/// The browser mirror's router: the shared routes + permissive CORS (loopback only, so a
/// wildcard origin is safe; the extension origin is `chrome-extension://…`).
pub fn build_cors_router(backend: Arc<WalletBackend>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_headers(Any);
    build_router(backend).layer(cors)
}

/// Serve the mTLS `9257` listener (Sage byte-parity) on a pre-bound std listener.
pub async fn serve_mtls(
    backend: Arc<WalletBackend>,
    listener: std::net::TcpListener,
    cert: &SharedCert,
) -> std::io::Result<()> {
    let config = build_server_config(cert).map_err(|e| std::io::Error::other(e.to_string()))?;
    let rustls_config = RustlsConfig::from_config(Arc::new(config));
    axum_server::from_tcp_rustls(listener, rustls_config)
        .serve(build_router(backend).into_make_service())
        .await
}

/// Serve the plain-HTTP + CORS browser mirror on a pre-bound tokio listener.
pub async fn serve_http(
    backend: Arc<WalletBackend>,
    listener: tokio::net::TcpListener,
) -> std::io::Result<()> {
    axum::serve(listener, build_cors_router(backend)).await
}

/// Bring up BOTH transports on loopback (design C.3): the mTLS `9257` listener and the
/// plain-HTTP+CORS browser mirror, each dispatching the shared handler set. Returns once
/// either listener exits. Both bind `127.0.0.1` only.
pub async fn serve_dual(
    backend: Arc<WalletBackend>,
    mtls_port: u16,
    http_port: u16,
    cert: SharedCert,
) -> std::io::Result<()> {
    let mtls_listener = std::net::TcpListener::bind(("127.0.0.1", mtls_port))?;
    let http_listener = tokio::net::TcpListener::bind(("127.0.0.1", http_port)).await?;
    let mtls = {
        let backend = backend.clone();
        tokio::spawn(async move { serve_mtls(backend, mtls_listener, &cert).await })
    };
    let http = tokio::spawn(async move { serve_http(backend, http_listener).await });
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
        let base = build_router(backend.clone());
        let cors = build_cors_router(backend.clone());
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
        let (status, body) = oneshot_body(build_router(backend), "get_secret_key").await;
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
        // The 9257 listener's rustls config (shared-cert client-auth verifier + server
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
        tokio::spawn(serve_http(backend, listener));

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
}
