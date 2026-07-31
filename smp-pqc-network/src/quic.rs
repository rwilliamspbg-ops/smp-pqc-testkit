//! QUIC handshake scanning for PQC/hybrid key-exchange support.
//!
//! Uses quinn with rustls backend to perform QUIC handshakes and inspect
//! the negotiated key-exchange group.
//!
//! **Note**: Full KEX group reporting requires rustls's `__rustls-post-quantum-test`
//! feature flag (not available in stable releases). This implementation performs
//! the handshake and reports success/failure; the negotiated KEX group detection
//! is limited without the test feature.
//!
//! Only scan hosts you own or are explicitly authorized to test.

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use serde::Serialize;

/// Result of probing a single QUIC endpoint's negotiated key-exchange algorithm.
#[derive(Debug, Serialize)]
pub struct QuicScanReport {
    pub host: String,
    pub port: u16,
    pub handshake_completed: bool,
    pub negotiated_kex: Option<String>,
    pub is_pqc_hybrid: bool,
    pub error: Option<String>,
}

impl QuicScanReport {
    pub fn is_pqc(&self) -> bool {
        self.is_pqc_hybrid
    }
}

/// Probe `host:port`'s QUIC handshake and report the negotiated key-exchange algorithm.
///
/// Uses quinn with a rustls client configured with the aws-lc-rs crypto provider
/// (which provides ML-KEM/hybrid KEX groups). Performs a full QUIC handshake.
/// KEX group detection requires rustls's `__rustls-post-quantum-test` feature.
pub async fn scan_quic(host: &str, port: u16, timeout: Duration) -> QuicScanReport {
    let mut report = QuicScanReport {
        host: host.to_string(),
        port,
        handshake_completed: false,
        negotiated_kex: None,
        is_pqc_hybrid: false,
        error: None,
    };

    if let Err(e) = run_quic_scan(host, port, timeout, &mut report).await {
        report.error = Some(e.to_string());
    }
    report
}

async fn run_quic_scan(
    host: &str,
    port: u16,
    timeout: Duration,
    report: &mut QuicScanReport,
) -> anyhow::Result<()> {
    // Build rustls config with aws-lc-rs provider (provides ML-KEM/hybrid groups)
    let root_store = {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };

    let provider = rustls::crypto::CryptoProvider {
        kx_groups: aws_lc_rs::ALL_KX_GROUPS.to_vec(),
        ..aws_lc_rs::default_provider()
    };

    let rustls_config = RustlsClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Convert to quinn config
    let mut quic_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?,
    ));

    // Configure transport
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(timeout));
    quic_config.transport_config(Arc::new(transport));

    // Create endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quic_config);

    // Resolve address
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}:{port}"))?;

    // Set server name for SNI
    let server_name = ServerName::try_from(host.to_string())?;

    // Connect with timeout
    let connect_fut = endpoint.connect(addr, &server_name.to_str())?;
    let connection = tokio::time::timeout(timeout, connect_fut)
        .await
        .map_err(|_| anyhow::anyhow!("QUIC connection timed out"))??;

    // Wait for handshake to complete by polling handshake_data()
    // handshake_data() returns None while handshaking, Some when complete
    let start = std::time::Instant::now();
    loop {
        if connection.handshake_data().is_some() {
            break;
        }
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!("QUIC handshake timed out"));
        }
        // Yield to allow async progress
        tokio::task::yield_now().await;
    }

    report.handshake_completed = true;

    // Try to get negotiated KEX group from handshake data
    // This requires rustls's `__rustls-post-quantum-test` feature (not in stable)
    if let Some(handshake_data) = connection.handshake_data() {
        // Attempt to downcast to quinn's rustls HandshakeData
        if let Ok(_tls_info) = handshake_data.downcast::<quinn::crypto::rustls::HandshakeData>() {
            // The negotiated_key_exchange_group field is only available
            // with the `__rustls-post-quantum-test` feature on the rustls crate.
            // Since that feature is not available in stable releases, we report
            // the limitation via error instead of a placeholder string.
            report.negotiated_kex = None;
            report.error = Some(
                "KEX group detection requires rustls with __rustls-post-quantum-test feature (not available in stable releases)"
                    .to_string(),
            );
        }
    }

    // Gracefully close
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}
