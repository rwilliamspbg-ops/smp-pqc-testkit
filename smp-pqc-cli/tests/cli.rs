//! Integration tests that invoke the actual `smp-pqc` binary, exercising the
//! argument parsing and output paths that unit tests inside `smp-pqc-core`
//! never touch (main.rs had 0% coverage before this file existed).

use assert_cmd::Command;
use predicates::prelude::*;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ServerConfig, ServerConnection};
use std::io;
use std::net::TcpListener;
use std::sync::Arc;

fn cmd() -> Command {
    Command::cargo_bin("smp-pqc").unwrap()
}

/// Starts a local TLS server restricted to the given key-exchange group(s),
/// accepts one connection, completes the handshake, then exits. Returns the
/// port it's listening on. Used so `scan tls` integration tests don't depend
/// on any external host being reachable or PQC-capable.
fn spawn_test_tls_server(kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>) -> u16 {
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
    // Also the one place --report text is passed explicitly, exercising
    // ReportFormat::Text's Display impl (every other test either omits
    // --report, which now defaults via a raw string in merge_with_cli
    // without ever constructing a ReportFormat::Text value, or passes
    // --report json).
    cmd()
        .args([
            "test",
            "kem",
            "ml-kem-768",
            "--hybrid",
            "--iterations",
            "2",
            "--report",
            "text",
        ])
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
fn scan_tls_insecure_detects_hybrid_pqc_group_against_local_server() {
    let port = spawn_test_tls_server(vec![aws_lc_rs::kx_group::X25519MLKEM768]);
    let assert = cmd()
        .args([
            "scan",
            "tls",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--insecure",
            "--report",
            "json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["is_pqc_hybrid"], true);
    assert_eq!(parsed["negotiated_group"], "X25519MLKEM768");
}

#[test]
fn scan_tls_pqc_only_fails_when_server_has_no_pqc_support() {
    let port = spawn_test_tls_server(vec![aws_lc_rs::kx_group::X25519]);
    cmd()
        .args([
            "scan",
            "tls",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--insecure",
            "--pqc-only",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "did not negotiate a PQC/hybrid key-exchange group",
        ));
}

#[test]
fn scan_tls_without_insecure_rejects_self_signed_certificate() {
    let port = spawn_test_tls_server(vec![aws_lc_rs::kx_group::X25519MLKEM768]);
    cmd()
        .args(["scan", "tls", "127.0.0.1", "--port", &port.to_string()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TLS scan"));
}

#[test]
fn scan_tls_unreachable_host_fails_clearly() {
    cmd()
        .args([
            "scan",
            "tls",
            "127.0.0.1",
            "--port",
            "1",
            "--timeout-secs",
            "2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TLS scan"));
}

#[test]
fn scan_ssh_unreachable_host_fails_clearly() {
    // No local test-server coverage for the positive PQC-detection path
    // here, unlike scan tls -- russh's server API would need a full
    // handler (host key, auth) to stand one up, not attempted this pass.
    // Manually verified end-to-end against github.com's real SSH endpoint
    // instead (negotiated curve25519-sha256, correctly reported as
    // non-PQC -- github.com doesn't currently offer the hybrid KEX).
    cmd()
        .args([
            "scan",
            "ssh",
            "127.0.0.1",
            "--port",
            "1",
            "--timeout-secs",
            "2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("SSH scan"));
}

#[test]
fn scan_quic_unreachable_host_fails_clearly() {
    // Mirrors scan_tls_unreachable_host_fails_clearly / scan_ssh_unreachable_host_fails_clearly
    // above -- `scan quic`'s CLI dispatch (including spinning up its own
    // current-thread Tokio runtime) had no test coverage at all before this.
    cmd()
        .args([
            "scan",
            "quic",
            "127.0.0.1",
            "--port",
            "1",
            "--timeout-secs",
            "2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("QUIC scan"));
}

#[test]
fn config_file_sets_default_iterations_when_cli_flag_is_omitted() {
    // End-to-end coverage of main.rs's `--config` load call site (previously
    // untested -- only CliConfig::load's own unit tests exercised parsing).
    let config_path = std::env::temp_dir().join("smp-pqc-cli-test-config-default-iterations.toml");
    std::fs::write(&config_path, "iterations = 7\n").unwrap();

    let assert = cmd()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "test",
            "kem",
            "ml-kem-768",
            "--report",
            "json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["iterations"], 7);

    std::fs::remove_file(&config_path).ok();
}

#[test]
fn config_file_missing_fails_clearly() {
    let missing_path = std::env::temp_dir().join("smp-pqc-cli-test-config-does-not-exist.toml");
    std::fs::remove_file(&missing_path).ok();
    cmd()
        .args([
            "--config",
            missing_path.to_str().unwrap(),
            "test",
            "kem",
            "ml-kem-768",
            "--iterations",
            "1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read config file"));
}

#[test]
fn inventory_cbom_detects_our_own_pqc_crates() {
    // "cargo test" runs with CWD set to this crate's own directory, which
    // has no Cargo.lock of its own (it's a workspace member) -- the
    // workspace root, one level up, is where the real lockfile lives.
    let assert = cmd().args(["inventory", "..", "--cbom"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["bomFormat"], "CycloneDX");
    let names: Vec<&str> = parsed["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"ml-kem"));
    assert!(names.contains(&"ml-dsa"));
    assert!(names.contains(&"slh-dsa"));
}

#[test]
fn inventory_text_summary_reports_counts() {
    let assert = cmd().args(["inventory", ".."]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.contains("total dependencies"));
    assert!(stdout.contains("ml-kem"));
}

#[test]
fn inventory_missing_lockfile_fails_clearly() {
    let dir = std::env::temp_dir().join("smp-pqc-cli-inventory-test-empty-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cmd()
        .args(["inventory", dir.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no Cargo.lock found"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inventory_output_flag_writes_to_file() {
    let out_path = std::env::temp_dir().join("smp-pqc-cli-inventory-test-output.cdx.json");
    let _ = std::fs::remove_file(&out_path);
    cmd()
        .args([
            "inventory",
            "..",
            "--cbom",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let contents = std::fs::read_to_string(&out_path).expect("output file should exist");
    assert!(contents.contains("CycloneDX"));
    std::fs::remove_file(&out_path).ok();
}

#[test]
fn verify_formal_points_to_the_real_lean_proofs() {
    cmd()
        .args(["verify", "--formal"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("smp-pqc-verify/"));
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
fn verify_all_runs_core_kem_and_sig_tests_and_reports_pass() {
    // The plain, no-flags invocation -- run_verify_all's baseline path
    // (core KEM + SIG tests, including the large-stack SIG worker thread)
    // was entirely untested before this: no test invoked `verify-all` at
    // all, despite it being documented as "a meta-command for CI
    // integration."
    let assert = cmd().arg("verify-all").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.contains("Running core KEM tests"));
    assert!(stdout.contains("Running core SIG tests"));
    assert!(stdout.contains("=== verify-all result: PASS ==="));
}

#[test]
fn verify_all_with_inventory_flag_and_no_lockfile_reports_failure_without_failing_the_command() {
    // Default CWD under `cargo test` is this crate's own directory, which
    // has no Cargo.lock of its own (see inventory_cbom_detects_our_own_pqc_crates
    // above) -- so `--inventory` here exercises the "Inventory failed"
    // branch specifically. Inventory failure must not affect verify-all's
    // own pass/fail verdict (it isn't factored into all_passed).
    let assert = cmd().args(["verify-all", "--inventory"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.contains("Inventory failed"));
}

#[test]
fn verify_all_with_bench_scan_inventory_flags_prints_planned_messages_and_runs_inventory() {
    // Run from the workspace root (has a real Cargo.lock) to exercise the
    // "Inventory completed successfully" branch instead, alongside the
    // --bench/--scan planned-message branches in the same process.
    let assert = cmd()
        .args(["verify-all", "--bench", "--scan", "--inventory"])
        .current_dir("..")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.contains("Benchmarks requested"));
    assert!(stdout.contains("Network scans requested"));
    assert!(stdout.contains("Inventory completed successfully"));
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
