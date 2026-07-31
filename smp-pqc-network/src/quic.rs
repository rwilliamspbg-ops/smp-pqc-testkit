//! QUIC handshake scanning for PQC/hybrid key-exchange support (STUB).
//!
//! This is a placeholder implementation. Full QUIC scanning using quinn
//! with rustls backend is planned for Phase 3 of the roadmap.
//!
//! Only scan hosts you own or are explicitly authorized to test.

use std::time::Duration;

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
/// **NOT YET IMPLEMENTED**: Returns an error indicating this feature is planned.
/// Full implementation will use quinn with rustls backend to inspect the
/// negotiated KEX group during the QUIC handshake.
pub async fn scan_quic(_host: &str, _port: u16, _timeout: Duration) -> QuicScanReport {
    QuicScanReport {
        host: _host.to_string(),
        port: _port,
        handshake_completed: false,
        negotiated_kex: None,
        is_pqc_hybrid: false,
        error: Some(
            "QUIC scanning not yet implemented (planned for Phase 3). \
             Will use quinn crate with rustls backend to inspect negotiated KEX group."
                .to_string(),
        ),
    }
}
