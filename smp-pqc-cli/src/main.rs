use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use smp_pqc_core::{kem, sig};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "smp-pqc", version, about = "Sovereign Mohawk PQC test kit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run correctness roundtrip tests against a KEM or signature algorithm.
    Test {
        #[command(subcommand)]
        kind: TestKind,
    },
    /// Performance benchmarking (Criterion + AF_XDP harness).
    Bench {
        /// Use the AF_XDP zero-copy datapath benchmark. Linux-only.
        #[arg(long)]
        afxdp: bool,
        /// Compare against classical (non-PQC) algorithms.
        #[arg(long)]
        compare_classical: bool,
    },
    /// Network handshake scanning (TLS/SSH) for PQC/hybrid support.
    Scan {
        #[command(subcommand)]
        kind: ScanKind,
    },
    /// Scan a codebase and produce a cryptography inventory / CBOM.
    Inventory {
        path: String,
        #[arg(long)]
        cbom: bool,
        #[arg(long)]
        output: Option<String>,
    },
    /// Formal verification hooks (Lean4/TLA+).
    Verify {
        #[arg(long)]
        formal: bool,
    },
    /// TEE harness: run inside a trusted execution environment and attest results.
    TeeRun {
        #[arg(long)]
        attest: bool,
    },
}

#[derive(Subcommand)]
enum TestKind {
    /// Test a KEM algorithm (ML-KEM-512/768/1024).
    Kem {
        algo: String,
        /// Also run the X25519 + ML-KEM-768 hybrid instead of (or alongside) the bare algorithm.
        #[arg(long)]
        hybrid: bool,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        report: ReportFormat,
    },
    /// Test a signature algorithm (ML-DSA-44/65/87, SLH-DSA-*).
    Sig {
        algo: String,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        report: ReportFormat,
    },
}

#[derive(Subcommand)]
enum ScanKind {
    /// Scan a TLS endpoint's negotiated group for PQC/hybrid key exchange support.
    ///
    /// Only scan hosts you own or are explicitly authorized to test.
    Tls {
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Exit non-zero if the negotiated group is not PQC/hybrid.
        #[arg(long)]
        pqc_only: bool,
        /// Skip certificate validation. Only use against hosts you control
        /// (e.g. a local test server with a self-signed certificate) --
        /// this provides no protection against a man-in-the-middle.
        #[arg(long)]
        insecure: bool,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        report: ReportFormat,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Test { kind } => run_test(kind),
        Command::Bench { afxdp, .. } => {
            if afxdp {
                bail!(
                    "AF_XDP benchmarking requires Linux (XDP/eBPF) and is not implemented yet \
                     (planned for Phase 3 of the roadmap). Run this on a Linux host/WSL2 once \
                     smp-pqc-bench lands."
                );
            }
            bail!(
                "Criterion-based benchmarking is not implemented yet (planned for Phase 3). \
                 Use `smp-pqc test kem|sig ... --iterations N` for correctness + rough timing in the meantime."
            );
        }
        Command::Scan { kind } => match kind {
            ScanKind::Tls {
                host,
                port,
                pqc_only,
                insecure,
                timeout_secs,
                report,
            } => {
                let timeout = Duration::from_secs(timeout_secs);
                let r = if insecure {
                    smp_pqc_network::scan::scan_tls_insecure(&host, port, timeout)
                } else {
                    smp_pqc_network::scan::scan_tls(&host, port, timeout)
                };
                let passed = r.error.is_none() && (!pqc_only || r.is_pqc());
                print_report(&r, passed, report)?;
                if let Some(err) = &r.error {
                    bail!("TLS scan of {host}:{port} failed: {err}");
                }
                if pqc_only && !r.is_pqc() {
                    bail!(
                        "{host}:{port} did not negotiate a PQC/hybrid key-exchange group \
                         (got {:?})",
                        r.negotiated_group
                    );
                }
                Ok(())
            }
        },
        Command::Inventory { .. } => {
            bail!("CBOM/inventory generation is not implemented yet (planned for Phase 4).");
        }
        Command::Verify { .. } => {
            bail!(
                "Formal verification hooks (Lean4/TLA+) are not implemented yet (planned for \
                 Phase 4). Scope: TLA+ specs for protocol state machines (e.g. the hybrid \
                 handshake), plus citing libcrux's existing HACL*-derived proofs for primitives \
                 -- not re-proving primitives from scratch."
            );
        }
        Command::TeeRun { .. } => {
            bail!(
                "TEE attestation is not implemented yet (planned for Phase 4) and requires \
                 Linux + TEE-capable hardware (SGX/SEV/TrustZone)."
            );
        }
    }
}

fn run_test(kind: TestKind) -> Result<()> {
    match kind {
        TestKind::Kem {
            algo,
            hybrid,
            iterations,
            report,
        } => {
            if hybrid {
                if !matches!(algo.parse(), Ok(kem::KemAlgorithm::MlKem768)) {
                    bail!(
                        "--hybrid only supports ml-kem-768 today (X25519 + ML-KEM-768); \
                         got algo '{algo}'. Pass 'ml-kem-768' explicitly, or drop --hybrid."
                    );
                }
                let r = kem::run_hybrid(iterations);
                print_report(&r, r.failures == 0, report)?;
                check_hybrid_report(&r)?;
            } else {
                let algorithm: kem::KemAlgorithm = algo.parse()?;
                let r = kem::run(algorithm, iterations);
                print_report(&r, r.all_passed(), report)?;
                check_kem_report(&r)?;
            }
            Ok(())
        }
        TestKind::Sig {
            algo,
            iterations,
            report,
        } => {
            let algorithm: sig::SigAlgorithm = algo.parse()?;
            let r = sig::run(algorithm, iterations);
            print_report(&r, r.all_passed(), report)?;
            check_sig_report(&r)?;
            Ok(())
        }
    }
}

/// Turns a failed [`kem::KemReport`] into an error with a human-readable
/// count. Split out from `run_test` so the failure-message formatting is
/// unit-testable against a synthetic failing report, without needing to
/// actually break a KEM implementation to exercise this path.
fn check_kem_report(r: &kem::KemReport) -> Result<()> {
    if !r.all_passed() {
        bail!(
            "{} of {} {} roundtrips failed",
            r.failures,
            r.iterations,
            r.algorithm.name()
        );
    }
    Ok(())
}

/// See [`check_kem_report`]; same rationale for the hybrid KEM path.
fn check_hybrid_report(r: &kem::HybridKemReport) -> Result<()> {
    if r.failures != 0 {
        bail!(
            "{} of {} hybrid KEM roundtrips failed",
            r.failures,
            r.iterations
        );
    }
    Ok(())
}

/// See [`check_kem_report`]; same rationale for the signature path.
fn check_sig_report(r: &sig::SigReport) -> Result<()> {
    if !r.all_passed() {
        bail!(
            "{} verify failures, {} tamper-acceptances out of {} iterations for {}",
            r.verify_failures,
            r.tamper_acceptances,
            r.iterations,
            r.algorithm.name()
        );
    }
    Ok(())
}

fn print_report<T: serde::Serialize + std::fmt::Debug>(
    report: &T,
    passed: bool,
    format: ReportFormat,
) -> Result<()> {
    match format {
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        ReportFormat::Text => {
            println!("{report:#?}");
            println!("result: {}", if passed { "PASS" } else { "FAIL" });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These synthesize a failing report directly rather than driving a real
    // algorithm to fail (which would mean the algorithm is actually broken),
    // to check the CLI's own error-message formatting in isolation.

    #[test]
    fn check_kem_report_passes_silently_when_all_passed() {
        let r = kem::run(kem::KemAlgorithm::MlKem512, 3);
        assert!(check_kem_report(&r).is_ok());
    }

    #[test]
    fn check_kem_report_errors_with_counts_and_algorithm_name_on_failure() {
        let r = kem::KemReport {
            algorithm: kem::KemAlgorithm::MlKem768,
            iterations: 10,
            successes: 7,
            failures: 3,
        };
        let err = check_kem_report(&r).unwrap_err().to_string();
        assert!(err.contains("3 of 10"));
        assert!(err.contains("ML-KEM-768"));
    }

    #[test]
    fn check_sig_report_errors_on_tamper_acceptance() {
        let r = sig::SigReport {
            algorithm: sig::SigAlgorithm::MlDsa65,
            iterations: 5,
            verify_successes: 5,
            verify_failures: 0,
            tamper_rejections: 4,
            tamper_acceptances: 1,
        };
        let err = check_sig_report(&r).unwrap_err().to_string();
        assert!(err.contains("0 verify failures"));
        assert!(err.contains("1 tamper-acceptances"));
        assert!(err.contains("ML-DSA-65"));
    }

    #[test]
    fn check_hybrid_report_errors_with_counts_on_failure() {
        let r = kem::HybridKemReport {
            iterations: 8,
            successes: 6,
            failures: 2,
            combined_secret_len: 64,
        };
        let err = check_hybrid_report(&r).unwrap_err().to_string();
        assert!(err.contains("2 of 8"));
    }
}
