use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use smp_pqc_core::{kem, sig};

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
    /// Scan a TLS endpoint's negotiated groups for PQC/hybrid key exchange support.
    Tls {
        host: String,
        #[arg(long)]
        pqc_only: bool,
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
            ScanKind::Tls { host, .. } => {
                bail!(
                    "TLS scanning for '{host}' is not implemented yet (planned for Phase 3). \
                     When implemented, only scan hosts you own or are authorized to test."
                );
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
                let r = kem::run_hybrid(iterations);
                print_report(&r, r.failures == 0, report)?;
                if r.failures != 0 {
                    bail!(
                        "{} of {} hybrid KEM roundtrips failed",
                        r.failures,
                        r.iterations
                    );
                }
            } else {
                let algorithm: kem::KemAlgorithm = algo.parse()?;
                let r = kem::run(algorithm, iterations);
                print_report(&r, r.all_passed(), report)?;
                if !r.all_passed() {
                    bail!(
                        "{} of {} {} roundtrips failed",
                        r.failures,
                        r.iterations,
                        algorithm.name()
                    );
                }
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
            if !r.all_passed() {
                bail!(
                    "{} verify failures, {} tamper-acceptances out of {} iterations for {}",
                    r.verify_failures,
                    r.tamper_acceptances,
                    r.iterations,
                    algorithm.name()
                );
            }
            Ok(())
        }
    }
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
