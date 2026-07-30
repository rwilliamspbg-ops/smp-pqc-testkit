//! TLS handshake scanning for PQC/hybrid key-exchange support.
//!
//! Only inspects which key-exchange group is negotiated during the TLS 1.3
//! handshake -- this is read-only network probing, not an attempt to
//! establish an application-layer session. See the crate's authorized-use
//! note in the workspace threat model: only scan hosts you own or are
//! explicitly authorized to test.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::aws_lc_rs;
use rustls::{ClientConfig, ClientConnection, NamedGroup, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;

/// Result of probing a single TLS endpoint's negotiated key-exchange group.
#[derive(Debug, Serialize)]
pub struct TlsScanReport {
    pub host: String,
    pub port: u16,
    /// True once the TLS 1.3 handshake completed far enough to learn the
    /// negotiated key-exchange group. Note this can be true even when
    /// `error` is set to a later, non-fatal I/O condition (e.g. the peer
    /// closing the connection right after the handshake, before any
    /// application data was exchanged) -- what matters for this tool is the
    /// negotiated group, not a fully round-tripped application session.
    pub handshake_completed: bool,
    pub tls_version: Option<String>,
    pub negotiated_group: Option<String>,
    pub is_pqc_hybrid: bool,
    pub is_pure_pqc: bool,
    pub error: Option<String>,
}

impl TlsScanReport {
    pub fn is_pqc(&self) -> bool {
        self.is_pqc_hybrid || self.is_pure_pqc
    }
}

fn classify_group(group: NamedGroup) -> (bool, bool) {
    let is_hybrid = matches!(
        group,
        NamedGroup::X25519MLKEM768 | NamedGroup::secp256r1MLKEM768
    );
    let is_pure = matches!(
        group,
        NamedGroup::MLKEM512 | NamedGroup::MLKEM768 | NamedGroup::MLKEM1024
    );
    (is_hybrid, is_pure)
}

/// Probe `host:port`'s TLS 1.3 handshake, offering every key-exchange group
/// the `aws-lc-rs` crypto provider knows about (classical, hybrid, and pure
/// post-quantum) rather than just rustls's PQC-preferring default list, so a
/// scan reports everything a server is willing to negotiate, not only what a
/// default rustls client would pick first.
///
/// Certificate chains are validated against the Mozilla root store bundled
/// via `webpki-roots` (no reliance on the OS trust store). For scanning
/// local test infrastructure with a self-signed certificate, see
/// [`scan_tls_insecure`].
pub fn scan_tls(host: &str, port: u16, timeout: Duration) -> TlsScanReport {
    let root_store = {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };
    scan_tls_with_verifier(host, port, timeout, root_store, false)
}

/// Same as [`scan_tls`], but skips certificate verification entirely. Only
/// use this against hosts you control (e.g. a local test server with a
/// self-signed certificate) -- it provides no protection against a
/// man-in-the-middle, which defeats the purpose of TLS for anything else.
pub fn scan_tls_insecure(host: &str, port: u16, timeout: Duration) -> TlsScanReport {
    scan_tls_with_verifier(host, port, timeout, RootCertStore::empty(), true)
}

fn scan_tls_with_verifier(
    host: &str,
    port: u16,
    timeout: Duration,
    root_store: RootCertStore,
    insecure: bool,
) -> TlsScanReport {
    let mut report = TlsScanReport {
        host: host.to_string(),
        port,
        handshake_completed: false,
        tls_version: None,
        negotiated_group: None,
        is_pqc_hybrid: false,
        is_pure_pqc: false,
        error: None,
    };

    if let Err(e) = run_scan(host, port, timeout, root_store, insecure, &mut report) {
        report.error = Some(e.to_string());
    }
    report
}

fn run_scan(
    host: &str,
    port: u16,
    timeout: Duration,
    root_store: RootCertStore,
    insecure: bool,
    report: &mut TlsScanReport,
) -> anyhow::Result<()> {
    let provider = rustls::crypto::CryptoProvider {
        kx_groups: aws_lc_rs::ALL_KX_GROUPS.to_vec(),
        ..aws_lc_rs::default_provider()
    };

    let config_builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?;

    let config = if insecure {
        config_builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::AcceptAnyServerCert::new(
                aws_lc_rs::default_provider(),
            )))
            .with_no_client_auth()
    } else {
        config_builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let server_name = ServerName::try_from(host.to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}:{port}"))?;
    let mut sock = TcpStream::connect_timeout(&addr, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    while conn.is_handshaking() {
        match conn.complete_io(&mut sock) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !conn.is_handshaking() => break,
            Err(e) => return Err(e.into()),
        }
    }

    report.handshake_completed = true;
    report.tls_version = conn.protocol_version().map(|v| format!("{v:?}"));
    if let Some(group) = conn.negotiated_key_exchange_group() {
        let name = group.name();
        report.negotiated_group = Some(format!("{name:?}"));
        let (hybrid, pure) = classify_group(name);
        report.is_pqc_hybrid = hybrid;
        report.is_pure_pqc = pure;
    }
    Ok(())
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Accepts any server certificate. Only reachable via
    /// [`super::scan_tls_insecure`], which is documented as unsafe to use
    /// against anything but hosts you control.
    #[derive(Debug)]
    pub(super) struct AcceptAnyServerCert(CryptoProvider);

    impl AcceptAnyServerCert {
        pub(super) fn new(provider: CryptoProvider) -> Self {
            Self(provider)
        }
    }

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
