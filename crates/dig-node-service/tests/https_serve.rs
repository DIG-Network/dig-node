//! End-to-end tests for the local HTTPS surface `https://dig.local` (#624, the #620 epic).
//!
//! These prove the transport contract the design requires:
//!
//! - the node serves its app over TLS with a dig-cert leaf (a client trusting the per-machine
//!   CA gets a valid chain and the real content);
//! - a leaf ROTATION is picked up LIVE — the served certificate changes without the listener
//!   being torn down or a connection dropped;
//! - loading the leaf FAILS SOFT when no CA/leaf is present (covered as a unit test in
//!   `src/tls.rs`; here we assert the positive serve + rotation path end-to-end).
//!
//! The listener binds an ephemeral loopback port (`127.0.0.1:0`) rather than the privileged
//! `127.0.0.2:443` so the test needs no elevation; `127.0.0.1` is in the leaf's SAN set, so the
//! chain validates identically.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use dig_cert::{generate_ca, issue_leaf, load_server_config, ParsedCa, TlsPaths};
use rustls::pki_types::{CertificateDer, ServerName};
use time::OffsetDateTime;

/// Write a freshly generated per-machine CA + leaf into `paths`, returning the CA cert PEM
/// (a client trusts this to validate the served leaf).
fn provision(paths: &TlsPaths) -> String {
    std::fs::create_dir_all(&paths.root).unwrap();
    let now = OffsetDateTime::now_utc();
    let ca = generate_ca("test-host", now).unwrap();
    std::fs::write(paths.ca_cert(), &ca.cert_pem).unwrap();
    std::fs::write(paths.ca_key(), &ca.key_pem).unwrap();
    write_leaf(paths, &ca.cert_pem, &ca.key_pem);
    ca.cert_pem
}

/// Issue a fresh leaf from the on-disk CA and write it — used to simulate a rotation.
fn write_leaf(paths: &TlsPaths, ca_cert_pem: &str, ca_key_pem: &str) {
    let parsed = ParsedCa::from_pem(ca_cert_pem, ca_key_pem).unwrap();
    let leaf = issue_leaf(&parsed, OffsetDateTime::now_utc()).unwrap();
    std::fs::write(paths.leaf_cert(), &leaf.cert_pem).unwrap();
    std::fs::write(paths.leaf_key(), &leaf.key_pem).unwrap();
}

/// A client-side verifier that accepts ANY server certificate. This probe's sole job is to
/// CAPTURE the leaf the server presents (to assert it changed after a rotation) — chain
/// validation is proven separately by the trusting `reqwest` request. Decoupling capture from
/// validation also sidesteps rustls-webpki's rejection of the leaf's `*.dig` wildcard SAN
/// (dig-cert SPEC §3.1, a known + regression-pinned limitation).
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Complete a TLS handshake against `addr` and return the leaf certificate the server presented,
/// so a test can assert the served leaf actually changed after a rotation (cert capture only —
/// see [`AcceptAnyServerCert`]).
fn served_leaf_der(addr: SocketAddr) -> Vec<u8> {
    use std::io::{Read, Write};
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
    .with_no_client_auth();
    let server_name = ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into());
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    // Drive the handshake by exchanging a minimal request; the server closes the connection,
    // so the read may end in an error we deliberately ignore — the cert is captured regardless.
    tls.write_all(b"GET /health HTTP/1.1\r\nHost: dig.local\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf);
    conn.peer_certificates()
        .expect("server presented a certificate")[0]
        .to_vec()
}

// A multi-threaded runtime is required: the TLS listener runs as a spawned task while the test
// drives requests, and the synchronous rustls cert-capture probe (`served_leaf_der`) is run on a
// blocking worker via `spawn_blocking` so it never starves the server on a shared executor thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_serves_content_and_a_rotation_is_picked_up_live() {
    let dir = tempfile::tempdir().unwrap();
    let paths = TlsPaths::under(dir.path());
    let ca_pem = provision(&paths);

    // Build the reloadable rustls config from the leaf (the same call `crate::tls` makes) and
    // keep the resolver handle so the test can drive a rotation on the SAME live config.
    let (config, resolver) = load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

    let app = Router::new().route("/health", get(|| async { "dig-node-ok" }));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(tokio::sync::Notify::new());

    let server = {
        let rustls_config = rustls_config.clone();
        let app = app.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            dig_node_service::server::serve_https(listener, rustls_config, app, shutdown).await
        })
    };
    // Let the listener come up.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // A client trusting the per-machine CA gets a valid chain and the real content.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://127.0.0.1:{}/health", addr.port()))
        .send()
        .await
        .expect("HTTPS request succeeds over the dig-cert leaf");
    assert!(resp.status().is_success());
    assert_eq!(resp.text().await.unwrap(), "dig-node-ok");

    // Capture the leaf currently served, then ROTATE: issue a fresh leaf on disk and reload the
    // shared resolver — exactly what dig-cert's renewal manager does on a real rotation.
    let ca_key_pem = std::fs::read_to_string(paths.ca_key()).unwrap();
    let before = tokio::task::spawn_blocking(move || served_leaf_der(addr))
        .await
        .unwrap();
    write_leaf(&paths, &ca_pem, &ca_key_pem);
    resolver.reload().expect("hot-reload the rotated leaf");

    // The SAME listener is still up and now presents the NEW leaf — rotation caused no downtime.
    let after = tokio::task::spawn_blocking(move || served_leaf_der(addr))
        .await
        .unwrap();
    assert_ne!(before, after, "the served leaf changed after a rotation");

    let resp = client
        .get(format!("https://127.0.0.1:{}/health", addr.port()))
        .send()
        .await
        .expect("HTTPS still serves after the live rotation");
    assert!(resp.status().is_success());
    assert_eq!(resp.text().await.unwrap(), "dig-node-ok");

    shutdown.notify_waiters();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(6), server).await;
}
