//! Integration tests that invoke the actual `smp-pqc` binary, exercising the
//! argument parsing and output paths that unit tests inside `smp-pqc-core`
//! never touch (main.rs had 0% coverage before this file existed).

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("smp-pqc").unwrap()
}

#[test]
fn test_kem_json_report_is_valid_json_and_passes() {
    let assert = cmd()
        .args([
            "test",
            "kem",
            "ml-kem-768",
            "--iterations",
            "5",
            "--report",
            "json",
        ])
        .assert()
        .success();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\nstdout: {stdout}"));
    assert_eq!(parsed["algorithm"], "MlKem768");
    assert_eq!(parsed["iterations"], 5);
    assert_eq!(parsed["failures"], 0);
}

#[test]
fn test_kem_unknown_algorithm_fails_with_clear_message() {
    cmd()
        .args(["test", "kem", "not-a-real-algorithm", "--iterations", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown KEM algorithm"));
}

#[test]
fn test_kem_hybrid_with_mismatched_algo_fails_clearly() {
    // Regression test: --hybrid used to silently ignore the algo argument
    // and always run the ML-KEM-768 hybrid regardless of what was
    // requested. It must now reject the mismatch instead of substituting.
    cmd()
        .args(["test", "kem", "ml-kem-512", "--hybrid", "--iterations", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("only supports ml-kem-768"));
}

#[test]
fn test_kem_hybrid_with_matching_algo_succeeds() {
    cmd()
        .args(["test", "kem", "ml-kem-768", "--hybrid", "--iterations", "2"])
        .assert()
        .success();
}

#[test]
fn test_sig_json_report_is_valid_json_and_passes() {
    let assert = cmd()
        .args([
            "test",
            "sig",
            "ml-dsa-65",
            "--iterations",
            "3",
            "--report",
            "json",
        ])
        .assert()
        .success();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["algorithm"], "MlDsa65");
    assert_eq!(parsed["verify_failures"], 0);
    assert_eq!(parsed["tamper_acceptances"], 0);
}

#[test]
fn test_sig_unknown_algorithm_fails_with_clear_message() {
    cmd()
        .args(["test", "sig", "not-a-real-algorithm", "--iterations", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown signature algorithm"));
}

#[test]
fn bench_afxdp_fails_with_planned_phase_message_not_silent_success() {
    // These commands must never silently succeed or produce fabricated
    // output -- they should fail loudly with what's actually implemented.
    cmd()
        .args(["bench", "--afxdp"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented yet"));
}

#[test]
fn bench_without_flags_fails_with_criterion_planned_message() {
    cmd()
        .arg("bench")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Criterion-based benchmarking"));
}

#[test]
fn scan_tls_fails_with_planned_phase_message() {
    cmd()
        .args(["scan", "tls", "example.com"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented yet"));
}

#[test]
fn inventory_fails_with_planned_phase_message() {
    cmd()
        .args(["inventory", ".", "--cbom"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented yet"));
}

#[test]
fn verify_formal_fails_with_planned_phase_message() {
    cmd()
        .args(["verify", "--formal"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented yet"));
}

#[test]
fn tee_run_attest_fails_with_planned_phase_message() {
    cmd()
        .args(["tee-run", "--attest"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented yet"));
}

#[test]
fn no_args_prints_usage_and_fails() {
    cmd().assert().failure();
}

#[test]
fn help_flag_lists_all_top_level_subcommands() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("test"))
        .stdout(predicate::str::contains("bench"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("inventory"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("tee-run"));
}
