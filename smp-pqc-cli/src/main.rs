use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use smp_pqc_core::{kem, sig};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

mod config;
use config::CliConfig;

#[derive(Parser)]
#[command(name = "smp-pqc", version, about = "Sovereign Mohawk PQC test kit")]
struct Cli {
    /// Path to a TOML config file with default values for CLI options
    #[arg(long, global = true)]
    config: Option<PathBuf>,
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
    /// Network handshake scanning (TLS/SSH/QUIC) for PQC/hybrid support.
    Scan {
        #[command(subcommand)]
        kind: ScanKind,
    },
    /// Scan a Cargo.lock (or a directory containing one) and produce a
    /// cryptography inventory / CBOM.
    Inventory {
        /// Path to a Cargo.lock file, or a directory containing one.
        path: String,
        /// Emit a CycloneDX-shaped CBOM (JSON) instead of a human-readable summary.
        #[arg(long)]
        cbom: bool,
        /// Write output to this file instead of stdout.
        #[arg(long)]
        output: Option<String>,
    },
    /// Formal verification hooks (Lean4).
    Verify {
        #[arg(long)]
        formal: bool,
    },
    /// Run comprehensive verification: tests + benches (subset) + scans + inventory.
    /// This is a meta-command for CI integration.
    VerifyAll {
        /// Also run benchmarks (time-consuming).
        #[arg(long)]
        bench: bool,
        /// Also run network scans against localhost test servers.
        #[arg(long)]
        scan: bool,
        /// Run inventory on current workspace.
        #[arg(long)]
        inventory: bool,
        /// Output format for results.
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        report: ReportFormat,
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
    /// Scan an SSH endpoint's negotiated key-exchange algorithm for PQC/hybrid support.
    ///
    /// Only scan hosts you own or are explicitly authorized to test. Does
    /// not verify host identity (accepts any host key) -- see
    /// `smp-pqc-network::ssh`'s module docs for why.
    Ssh {
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Exit non-zero if the negotiated key-exchange algorithm is not PQC/hybrid.
        #[arg(long)]
        pqc_only: bool,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        report: ReportFormat,
    },
    /// Scan a QUIC endpoint's negotiated key-exchange algorithm for PQC/hybrid support.
    ///
    /// Only scan hosts you own or are explicitly authorized to test.
    /// NOT YET IMPLEMENTED: returns a clear error message.
    Quic {
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Exit non-zero if the negotiated key-exchange algorithm is not PQC/hybrid.
        #[arg(long)]
        pqc_only: bool,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        report: ReportFormat,
    },
}

#[derive(Clone, Copy, ValueEnum, Debug, serde::Serialize, serde::Deserialize)]
enum ReportFormat {
    Text,
    Json,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Text => write!(f, "text"),
            ReportFormat::Json => write!(f, "json"),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config file if specified
    let config = if let Some(config_path) = &cli.config {
        CliConfig::load(config_path)?
    } else {
        CliConfig::default()
    };

    match cli.command {
        Command::Test { kind } => run_test(kind, &config),
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
                let merged = config.merge_with_cli(
                    None,
                    Some(report.to_string()),
                    Some(timeout_secs),
                    Some(pqc_only),
                    Some(insecure),
                    None,
                    None,
                );
                let timeout = Duration::from_secs(merged.timeout_secs);
                let r = if merged.insecure {
                    smp_pqc_network::scan::scan_tls_insecure(&host, port, timeout)
                } else {
                    smp_pqc_network::scan::scan_tls(&host, port, timeout)
                };
                let passed = r.error.is_none() && (!merged.pqc_only || r.is_pqc());
                print_report(&r, passed, &merged.report)?;
                if let Some(err) = &r.error {
                    bail!("TLS scan of {host}:{port} failed: {err}");
                }
                if merged.pqc_only && !r.is_pqc() {
                    bail!(
                        "{host}:{port} did not negotiate a PQC/hybrid key-exchange group \
                         (got {:?})",
                        r.negotiated_group
                    );
                }
                Ok(())
            }
            ScanKind::Ssh {
                host,
                port,
                pqc_only,
                timeout_secs,
                report,
            } => {
                let merged = config.merge_with_cli(
                    None,
                    Some(report.to_string()),
                    Some(timeout_secs),
                    Some(pqc_only),
                    None,
                    None,
                    None,
                );
                let timeout = Duration::from_secs(merged.timeout_secs);
                let r = smp_pqc_network::ssh::scan_ssh(&host, port, timeout);
                let passed = r.error.is_none() && (!merged.pqc_only || r.is_pqc());
                print_report(&r, passed, &merged.report)?;
                if let Some(err) = &r.error {
                    bail!("SSH scan of {host}:{port} failed: {err}");
                }
                if merged.pqc_only && !r.is_pqc() {
                    bail!(
                        "{host}:{port} did not negotiate a PQC/hybrid key-exchange algorithm \
                         (got {:?})",
                        r.negotiated_kex
                    );
                }
                Ok(())
            }
            ScanKind::Quic {
                host,
                port,
                pqc_only,
                timeout_secs,
                report,
            } => {
                let merged = config.merge_with_cli(
                    None,
                    Some(report.to_string()),
                    Some(timeout_secs),
                    Some(pqc_only),
                    None,
                    None,
                    None,
                );
                let timeout = Duration::from_secs(merged.timeout_secs);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| anyhow::anyhow!("failed to start async runtime: {e}"))?;
                let r = rt.block_on(smp_pqc_network::quic::scan_quic(&host, port, timeout));
                let passed = r.error.is_none() && (!merged.pqc_only || r.is_pqc());
                print_report(&r, passed, &merged.report)?;
                if let Some(err) = &r.error {
                    bail!("QUIC scan of {host}:{port} failed: {err}");
                }
                if merged.pqc_only && !r.is_pqc() {
                    bail!(
                        "{host}:{port} did not negotiate a PQC/hybrid key-exchange algorithm \
                         (got {:?})",
                        r.negotiated_kex
                    );
                }
                Ok(())
            }
        },
        Command::Inventory { path, cbom, output } => {
            let merged = config.merge_with_cli(None, None, None, None, None, output, Some(cbom));
            run_inventory(&path, merged.cbom, merged.output.as_deref())
        }
        Command::Verify { .. } => {
            bail!(
                "This CLI does not invoke formal verification directly (a Lean 4 toolchain \
                 isn't assumed to be present at runtime). Real, machine-checked Lean 4 proofs \
                 do exist, though -- see smp-pqc-verify/ (run `lake build` there, or read \
                 smp-pqc-verify/README.md for what's actually proved: control-flow safety \
                 properties of the hybrid KEM combiner and signature-report aggregation logic, \
                 not proofs about the cryptographic primitives themselves)."
            );
        }
        Command::VerifyAll {
            bench,
            scan,
            inventory,
            report,
        } => run_verify_all(bench, scan, inventory, report, &config),
        Command::TeeRun { .. } => {
            bail!(
                "TEE attestation is not implemented yet (planned for Phase 4) and requires \
                 Linux + TEE-capable hardware (SGX/SEV/TrustZone)."
            );
        }
    }
}

fn run_test(kind: TestKind, config: &CliConfig) -> Result<()> {
    match kind {
        TestKind::Kem {
            algo,
            hybrid,
            iterations,
            report,
        } => {
            let merged = config.merge_with_cli(
                Some(iterations),
                Some(report.to_string()),
                None,
                None,
                None,
                None,
                None,
            );
            if hybrid {
                if !matches!(algo.parse(), Ok(kem::KemAlgorithm::MlKem768)) {
                    bail!(
                        "--hybrid only supports ml-kem-768 today (X25519 + ML-KEM-768); \
                         got algo '{algo}'. Pass 'ml-kem-768' explicitly, or drop --hybrid."
                    );
                }
                let r = kem::run_hybrid(merged.iterations);
                print_report(&r, r.failures == 0, &merged.report)?;
                check_hybrid_report(&r)?;
            } else {
                let algorithm: kem::KemAlgorithm = algo.parse()?;
                let r = kem::run(algorithm, merged.iterations);
                print_report(&r, r.all_passed(), &merged.report)?;
                check_kem_report(&r)?;
            }
            Ok(())
        }
        TestKind::Sig {
            algo,
            iterations,
            report,
        } => {
            let merged = config.merge_with_cli(
                Some(iterations),
                Some(report.to_string()),
                None,
                None,
                None,
                None,
                None,
            );
            let algorithm: sig::SigAlgorithm = algo.parse()?;
            let iterations = merged.iterations;
            let r = run_on_large_stack(move || sig::run(algorithm, iterations))?;
            print_report(&r, r.all_passed(), &merged.report)?;
            check_sig_report(&r)?;
            Ok(())
        }
    }
}

fn run_inventory(path: &str, cbom: bool, output: Option<&str>) -> Result<()> {
    let lockfile_path =
        smp_pqc_inventory::lockfile::resolve_lockfile_path(std::path::Path::new(path))?;
    let packages = smp_pqc_inventory::lockfile::parse_lockfile(&lockfile_path)?;

    let text = if cbom {
        let document = smp_pqc_inventory::cbom::build_cbom(&packages);
        serde_json::to_string_pretty(&document)?
    } else {
        let mut classified: Vec<_> = packages
            .iter()
            .filter_map(|p| smp_pqc_inventory::classify::classify(&p.name).map(|c| (p, c)))
            .collect();
        classified.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));

        let mut out = format!(
            "{} total dependencies, {} recognized as cryptographic\n\n",
            packages.len(),
            classified.len()
        );
        for (pkg, classification) in &classified {
            let category = if classification.is_post_quantum_capable {
                format!("{:?} [PQC]", classification.category)
            } else {
                format!("{:?}", classification.category)
            };
            out.push_str(&format!(
                "{:<24} {:<12} {:<28} {}\n",
                pkg.name, pkg.version, category, classification.note,
            ));
        }
        out
    };

    match output {
        Some(path) => std::fs::write(path, &text)
            .map_err(|e| anyhow::anyhow!("failed to write {path}: {e}"))?,
        None => println!("{text}"),
    }
    Ok(())
}

/// Turns a failed [`kem::KemReport`] into an error with a human-readable
/// count. Split out from `run_test` so the failure-message formatting is
/// unit-testable against a synthetic failing _, without needing to
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
    format: &str,
) -> Result<()> {
    match format {
        "json" | "Json" => println!("{}", serde_json::to_string_pretty(report)?),
        _ => {
            println!("{report:#?}");
            println!("result: {}", if passed { "PASS" } else { "FAIL" });
        }
    }
    Ok(())
}

fn run_verify_all(
    bench: bool,
    scan: bool,
    inventory: bool,
    report: ReportFormat,
    config: &CliConfig,
) -> Result<()> {
    let merged =
        config.merge_with_cli(None, Some(report.to_string()), None, None, None, None, None);
    let mut all_passed = true;

    // Run core KEM tests
    println!("=== Running core KEM tests ===");
    let kem_512 = kem::run(kem::KemAlgorithm::MlKem512, 3);
    let kem_768 = kem::run(kem::KemAlgorithm::MlKem768, 3);
    let kem_1024 = kem::run(kem::KemAlgorithm::MlKem1024, 3);
    let hybrid = kem::run_hybrid(3);

    print_report(&kem_512, kem_512.all_passed(), &merged.report)?;
    print_report(&kem_768, kem_768.all_passed(), &merged.report)?;
    print_report(&kem_1024, kem_1024.all_passed(), &merged.report)?;
    print_report(&hybrid, hybrid.failures == 0, &merged.report)?;

    all_passed &= kem_512.all_passed()
        && kem_768.all_passed()
        && kem_1024.all_passed()
        && hybrid.failures == 0;

    // Run core SIG tests (with larger stack on Windows to avoid stack overflow)
    println!("=== Running core SIG tests ===");
    let sig_results = run_sig_tests_with_large_stack()?;
    for (_name, r) in &sig_results {
        print_report(r, r.all_passed(), &merged.report)?;
        all_passed &= r.all_passed();
    }

    // Run benches if requested
    if bench {
        println!("=== Benchmarks requested (not implemented in CLI - use 'cargo bench') ===");
    }

    // Run scans if requested
    if scan {
        println!("=== Network scans requested (requires test servers) ===");
    }

    // Run inventory if requested
    if inventory {
        println!("=== Running inventory on current workspace ===");
        let inventory_result = run_inventory(".", false, None);
        if inventory_result.is_ok() {
            println!("Inventory completed successfully");
        } else {
            println!("Inventory failed: {:?}", inventory_result.err());
        }
    }

    println!(
        "=== verify-all result: {} ===",
        if all_passed { "PASS" } else { "FAIL" }
    );
    if !all_passed {
        bail!("verify-all failed: one or more checks did not pass");
    }
    Ok(())
}

/// Run `f` on a dedicated thread with a 16 MB stack instead of the calling
/// thread's default (1 MB on Windows), which SIG algorithms (ML-DSA's large
/// polynomial arrays, SLH-DSA's deep hash-tree recursion) can overflow --
/// reproduced with `smp-pqc test sig ml-dsa-65` under rustc 1.88.0, where
/// slightly different stack-frame codegen tips the main thread over the
/// limit even though the same call doesn't overflow under every toolchain.
fn run_on_large_stack<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let handle = thread::Builder::new()
        .name("smp-pqc-sig-worker".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(f)?;
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("SIG worker thread panicked"))
}

/// Run a representative subset of SIG tests on a large-stack thread (see
/// `run_on_large_stack`).
fn run_sig_tests_with_large_stack() -> Result<Vec<(String, sig::SigReport)>> {
    run_on_large_stack(|| {
        let mut results = Vec::new();
        // Run a representative subset: ML-DSA-65 (NIST recommended) and one SLH-DSA
        let algos = [
            sig::SigAlgorithm::MlDsa65,
            sig::SigAlgorithm::SlhDsaSha2128f,
        ];
        for algo in algos {
            let r = sig::run(algo, 3);
            results.push((algo.name().to_string(), r));
        }
        results
    })
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
