//! Integration tests for the TLS scanner against a local rustls server --
//! deliberately no external network dependency, both to keep CI reliable
//! and to avoid this test suite scanning any host that isn't ours.

use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ServerConfig, ServerConnection};

/// Starts a local TLS server on 127.0.0.1 restricted to exactly the given
/// key-exchange groups, accepts one connection, completes the handshake,
/// then exits. Returns the port it's listening on.
fn spawn_test_server(kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>) -> u16 {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("self-signed cert");
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let provider = rustls::crypto::CryptoProvider {
        kx_groups,
        ..aws_lc_rs::default_provider()
    };

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der.into())
        .expect("server config");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut conn = ServerConnection::new(Arc::new(config)).expect("server connection");
        loop {
            match conn.complete_io(&mut sock) {
                Ok(_) if !conn.is_handshaking() => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(_) => break,
            }
        }
    });

    port
}

#[test]
fn detects_hybrid_pqc_group_when_server_only_offers_it() {
    let port = spawn_test_server(vec![aws_lc_rs::kx_group::X25519MLKEM768]);
    let report =
        smp_pqc_network::scan::scan_tls_insecure("127.0.0.1", port, Duration::from_secs(5));
    assert!(report.error.is_none(), "scan error: {:?}", report.error);
    assert!(report.handshake_completed);
    assert!(
        report.is_pqc_hybrid,
        "expected hybrid PQC group: {report:?}"
    );
    assert!(!report.is_pure_pqc);
    assert!(report.is_pqc());
    assert_eq!(report.negotiated_group.as_deref(), Some("X25519MLKEM768"));
}

#[test]
fn detects_pure_pqc_group_when_server_only_offers_it() {
    let port = spawn_test_server(vec![aws_lc_rs::kx_group::MLKEM768]);
    let report =
        smp_pqc_network::scan::scan_tls_insecure("127.0.0.1", port, Duration::from_secs(5));
    assert!(report.error.is_none(), "scan error: {:?}", report.error);
    assert!(report.is_pure_pqc, "expected pure PQC group: {report:?}");
    assert!(!report.is_pqc_hybrid);
    assert!(report.is_pqc());
}

#[test]
fn reports_classical_only_when_server_has_no_pqc_support() {
    let port = spawn_test_server(vec![aws_lc_rs::kx_group::X25519]);
    let report =
        smp_pqc_network::scan::scan_tls_insecure("127.0.0.1", port, Duration::from_secs(5));
    assert!(report.error.is_none(), "scan error: {:?}", report.error);
    assert!(report.handshake_completed);
    assert!(!report.is_pqc());
    assert_eq!(report.negotiated_group.as_deref(), Some("X25519"));
}

#[test]
fn secure_scan_rejects_self_signed_certificate() {
    // scan_tls (not scan_tls_insecure) validates against the real Mozilla
    // root store, so a self-signed test cert must be rejected -- this is
    // exactly the safety property that makes the secure path trustworthy.
    let port = spawn_test_server(vec![aws_lc_rs::kx_group::X25519MLKEM768]);
    let report = smp_pqc_network::scan::scan_tls("127.0.0.1", port, Duration::from_secs(5));
    assert!(report.error.is_some());
    assert!(!report.handshake_completed);
}
