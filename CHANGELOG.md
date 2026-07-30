# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **SSH PQC/hybrid KEX scanning** (`scan ssh`, `smp-pqc-network::ssh`): uses
  `russh` 0.62's native `mlkem768x25519-sha256` support and its
  `Handler::kex_done` callback to report the actually negotiated
  key-exchange algorithm. Manually verified against `github.com`'s real SSH
  endpoint (negotiated `curve25519-sha256`, correctly reported as non-PQC).
  Does not verify host identity (accepts any host key). No local
  test-server coverage for the positive-detection path yet, unlike
  `scan tls` — see `docs/threat-model.md`.
- A real DudeCT-based constant-time check for ML-KEM-768 decapsulation
  (`smp-pqc-core/examples/dudect_ml_kem_decap.rs`): tests whether timing
  depends on ciphertext validity (the implicit-rejection/CCA2 concern).
  Measured result on this project's dev machine: no timing leak detected
  across 300,000+ samples (`max t` stayed under 2.7 vs. the t>5 threshold
  DudeCT's docs treat as a real signal) — see `docs/threat-model.md`'s
  side-channel section for the full result and its limits. Deliberately not
  wired into CI: shared runners are too noisy for trustworthy timing
  measurements.

### Known limitations

- Covers exactly one operation (ML-KEM-768 decapsulate) and one corruption
  pattern (single flipped byte). ML-KEM-512/1024 and ML-DSA/SLH-DSA
  sign/verify timing are not covered — extending to signatures needs care,
  since ML-DSA's rejection-sampling retries cause expected variable-time
  behavior that isn't itself a vulnerability, and distinguishing that from
  a real secret-dependent leak needs more rigor than a first pass gives it.

## [0.1.0] - 2026-07-30

Initial release. Every item below is real, working, and tested (`cargo test
--workspace` currently runs 70 tests across the Rust workspace, plus a
separately-verified Lean 4 proof suite) — see `README.md`'s Status section
for what's still explicitly *not* implemented, and why.

### Added

- **`smp-pqc-core`**: safe wrappers over the RustCrypto `ml-kem` (FIPS 203),
  `ml-dsa` (FIPS 204), and `slh-dsa` (FIPS 205) crates, plus an illustrative
  X25519 + ML-KEM-768 hybrid KEM. Proptest-based property tests, adversarial
  tests (wrong keys, corrupted ciphertext/signature bytes, ML-KEM implicit
  rejection), and a `basic_usage` library example.
- **`smp-pqc-core/tests/acvp.rs`**: NIST ACVP known-answer tests against
  sampled real reference vectors (`test-vectors/acvp/`) covering ML-KEM
  keygen/encapsulation/decapsulation and ML-DSA/SLH-DSA keygen/signature
  verification — validated against NIST's own ground truth, not just
  internal self-consistency.
- **`smp-pqc-core/fuzz`**: a `cargo-fuzz` target for the algorithm-name
  parsers (Linux-only; runs in CI, not on Windows).
- **`smp-pqc-cli`** (`smp-pqc` binary): `test kem`/`test sig` (correctness
  roundtrips), `scan tls` (TLS PQC/hybrid handshake scanning), `inventory`
  (cryptography inventory / CBOM generation). `bench`, `verify --formal`,
  and `tee-run --attest` exist as subcommands but exit with a specific,
  honest error rather than faking output — see below.
- **`smp-pqc-bench`**: Criterion benchmarks for keygen/encapsulate/decapsulate
  and keygen/sign/verify across every ML-KEM/ML-DSA/SLH-DSA parameter set,
  plus an X25519 classical baseline.
- **`smp-pqc-network`**: real TLS 1.3 handshake scanning via rustls 0.23's
  native ML-KEM/hybrid support (`aws-lc-rs` provider) — reports the actually
  negotiated key-exchange group, not just what was offered.
- **`smp-pqc-inventory`**: Cargo.lock scanning + crypto-crate classification
  + CycloneDX-shaped CBOM generation.
- **`smp-pqc-verify`**: a Lean 4 project with machine-checked, `sorry`-free
  proofs about `smp-pqc-core`'s control-flow logic (hybrid KEM combiner,
  signature-report aggregation) — not the cryptographic primitives
  themselves.
- CI (`.github/workflows/ci.yml`): build+test on Ubuntu and Windows,
  fmt+clippy+doc lint, a Linux-only fuzz smoke test, and a Lean
  verification job.

### Known limitations (by design, not oversight)

- SSH/QUIC scanning: not implemented. Blocked on integration work (async
  runtime, algorithm introspection), not on algorithm support — `russh`
  already implements the right hybrid KEX. See `docs/threat-model.md`.
- AF_XDP zero-copy benchmarking and TEE attestation: not implemented.
  Blocked on hardware even under WSL2 (investigated and confirmed during
  development — WSL2's virtual NIC and lack of enclave passthrough rule
  both out). See `docs/threat-model.md`.
- Side-channel/constant-time verification: not implemented. Needs dedicated
  timing-analysis tooling (e.g. dudect-style), not a unit test.
- `smp-pqc-verify` proves control-flow properties, not primitive security;
  it's hand-written Lean modeling the Rust logic, not extracted from it, so
  it can silently drift out of sync if the Rust changes without a matching
  Lean update — there's no automated check tying the two together yet.
