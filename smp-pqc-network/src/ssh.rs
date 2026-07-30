//! SSH handshake scanning for PQC/hybrid key-exchange support.
//!
//! Only inspects which key-exchange algorithm is negotiated during the SSH
//! transport handshake -- like [`crate::scan`], this is read-only network
//! probing, not an attempt to establish an authenticated session. See the
//! workspace threat model's authorized-use note: only scan hosts you own
//! or are explicitly authorized to test.
//!
//! **This scanner does not verify host identity.** It accepts any server
//! host key (there is no CA/root-of-trust equivalent for SSH the way
//! `webpki-roots` provides for TLS -- SSH normally relies on
//! TOFU/`known_hosts`, which isn't meaningful for a one-shot capability
//! probe). Treat results as informational about what algorithms a host
//! *offers*, not as an authenticated connection to that host.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handler};
use serde::Serialize;

/// Result of probing a single SSH endpoint's negotiated key-exchange algorithm.
#[derive(Debug, Serialize)]
pub struct SshScanReport {
    pub host: String,
    pub port: u16,
    pub handshake_completed: bool,
    pub negotiated_kex: Option<String>,
    pub is_pqc_hybrid: bool,
    pub error: Option<String>,
}

impl SshScanReport {
    pub fn is_pqc(&self) -> bool {
        self.is_pqc_hybrid
    }
}

/// The only hybrid PQC key-exchange algorithm russh currently implements
/// (matching OpenSSH 9.x+). There is no pure-PQC (non-hybrid) SSH kex
/// algorithm in wide deployment yet, unlike TLS's pure `MLKEM*` groups.
const PQC_HYBRID_KEX_NAMES: &[&str] = &["mlkem768x25519-sha256", "sntrup761x25519-sha512"];

struct ScanHandler {
    negotiated_kex: Arc<Mutex<Option<String>>>,
}

impl Handler for ScanHandler {
    type Error = russh::Error;

    /// Accepts any host key -- see this module's doc comment for why.
    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        *self
            .negotiated_kex
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(names.kex.as_ref().to_string());
        Ok(())
    }
}

/// Probe `host:port`'s SSH transport handshake and report the negotiated
/// key-exchange algorithm. Runs its own single-threaded Tokio runtime
/// internally (russh's client API is async; the rest of this CLI is not).
pub fn scan_ssh(host: &str, port: u16, timeout: Duration) -> SshScanReport {
    let mut report = SshScanReport {
        host: host.to_string(),
        port,
        handshake_completed: false,
        negotiated_kex: None,
        is_pqc_hybrid: false,
        error: None,
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            report.error = Some(format!("failed to start async runtime: {e}"));
            return report;
        }
    };

    match rt.block_on(run_scan(host, port, timeout)) {
        Ok(kex) => {
            report.handshake_completed = true;
            report.is_pqc_hybrid = PQC_HYBRID_KEX_NAMES.contains(&kex.as_str());
            report.negotiated_kex = Some(kex);
        }
        Err(e) => report.error = Some(e.to_string()),
    }
    report
}

async fn run_scan(host: &str, port: u16, timeout: Duration) -> anyhow::Result<String> {
    let negotiated_kex = Arc::new(Mutex::new(None));
    let handler = ScanHandler {
        negotiated_kex: negotiated_kex.clone(),
    };
    let config = Arc::new(client::Config::default());

    tokio::time::timeout(timeout, client::connect(config, (host, port), handler))
        .await
        .map_err(|_| anyhow::anyhow!("timed out connecting to {host}:{port}"))??;

    let kex = negotiated_kex
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    kex.ok_or_else(|| anyhow::anyhow!("connection closed before key exchange completed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_host_fails_clearly() {
        let report = scan_ssh("127.0.0.1", 1, Duration::from_secs(2));
        assert!(!report.handshake_completed);
        assert!(report.error.is_some());
    }
}
