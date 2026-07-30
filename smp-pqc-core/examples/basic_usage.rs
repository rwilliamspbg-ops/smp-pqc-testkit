//! Minimal example of using `smp-pqc-core` as a library, independent of the
//! `smp-pqc` CLI. Run with:
//!
//! ```bash
//! cargo run -p smp-pqc-core --example basic_usage
//! ```
//!
//! This exercises the same `kem::run`/`sig::run` API the CLI calls into --
//! useful as a starting point for embedding correctness checks directly in
//! another project (e.g. a CI gate that fails if a vendored crypto
//! dependency stops round-tripping) rather than shelling out to the CLI.

use smp_pqc_core::{kem, sig};

fn main() {
    println!("== ML-KEM-768 roundtrip ==");
    let kem_report = kem::run(kem::KemAlgorithm::MlKem768, 100);
    println!("{kem_report:#?}");
    assert!(kem_report.all_passed(), "ML-KEM-768 roundtrip should pass");

    println!("\n== X25519 + ML-KEM-768 hybrid roundtrip ==");
    let hybrid_report = kem::run_hybrid(100);
    println!("{hybrid_report:#?}");
    assert_eq!(hybrid_report.failures, 0, "hybrid roundtrip should pass");

    println!("\n== ML-DSA-65 sign/verify + tamper-detection ==");
    let sig_report = sig::run(sig::SigAlgorithm::MlDsa65, 100);
    println!("{sig_report:#?}");
    assert!(sig_report.all_passed(), "ML-DSA-65 roundtrip should pass");

    println!("\nAll roundtrips passed.");
}
