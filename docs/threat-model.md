# Threat model

## What this kit defends against

- **Harvest-now-decrypt-later**: an adversary recording classically-encrypted
  traffic today, to decrypt once a cryptographically relevant quantum computer
  (CRQC) exists. Mitigation: verify PQC/hybrid key exchange is actually
  negotiated and correct, not just configured.
- **Broken or non-conformant PQC implementations**: a library that claims
  FIPS 203/204/205 support but has a subtly wrong encoding, an RNG misuse, or
  fails on edge-case parameter sets. Mitigation: roundtrip + tamper-detection
  tests across all standardized parameter sets, and (planned) NIST ACVP known-
  answer tests.
- **Downgrade attacks**: a hybrid handshake that silently falls back to the
  classical leg alone. Mitigation: (planned, Phase 3) network scanners that
  verify the negotiated group is actually the PQC/hybrid one, not just
  offered.
- **Supply-chain drift**: unaudited or unmaintained crypto dependencies pulled
  into a downstream project. Mitigation: (planned, Phase 4) CBOM generation so
  downstream consumers know exactly which crypto primitives and versions are
  in use.

## What this kit does not defend against (out of scope)

- Physical side-channel attacks requiring hardware access (power analysis,
  EM emissions) — outside what a software test kit can exercise.
- Implementation bugs in the underlying crates themselves beyond what
  correctness/tamper tests can observe (this kit is a consumer/tester of
  `ml-kem`/`ml-dsa`/`slh-dsa`/`libcrux`, not an auditor of their internals).
- Key management, storage, or distribution — this kit tests algorithm
  correctness in isolation, not a full PKI or key lifecycle.

## Platform constraints (read before planning Phase 3/4 work)

- **AF_XDP** (planned `smp-pqc-network` zero-copy benchmarking) requires a
  Linux kernel with XDP/eBPF support. It will not build or run on Windows or
  macOS. Development must happen on Linux directly, in WSL2, or in Linux CI.
- **TEE attestation** (planned `smp-pqc-tee`) requires TEE-capable hardware
  (Intel SGX, AMD SEV, Arm TrustZone) and is Linux-only in practice.
- **TPM access** depends on OS/hardware TPM availability; the `tss-esapi`
  crate (not `tpm2-rs`, which does not appear to exist under that name — this
  was corrected from an earlier draft of the plan) is the maintained Rust TSS
  binding to evaluate here.
- **Formal verification** (planned `smp-pqc-verify`): proving PQC primitives
  from scratch in Lean4/TLA+ is a research-scale effort, not achievable in the
  timeframe of this roadmap. Realistic scope is (a) citing/consuming
  [libcrux](https://github.com/cryspen/libcrux)'s existing HACL*-derived
  formal proofs for primitives, and (b) writing TLA+ specs for
  protocol-level state machines this project actually controls (e.g. the
  hybrid handshake sequencing), not the underlying lattice/hash math.
- **Fuzzing** (`smp-pqc-core/fuzz`): `cargo-fuzz` requires a nightly toolchain
  and libFuzzer/AddressSanitizer, neither of which is usable on
  `x86_64-pc-windows-msvc`. The `parse_algorithm_names` fuzz target cannot be
  run on this project's primary Windows dev machine; CI runs it on
  `ubuntu-latest` instead (see `.github/workflows/ci.yml`'s
  `fuzz-smoke-test` job). Its scope is also narrow by design: it fuzzes the
  `FromStr` algorithm-name parsers, not any crypto encode/decode path, since
  smp-pqc-core doesn't expose byte-level key/ciphertext/signature
  serialization yet. That's a real gap for a "gold standard" test kit —
  once such an API exists (e.g. for CBOM/key export), it needs its own fuzz
  target and this note should be updated.

## Side-channel / constant-time testing (explicitly not done)

Nothing in this kit currently measures timing side-channels or verifies
constant-time behavior, and none of the tests here should be read as making
that claim. Doing this properly needs statistical timing-analysis tooling
(e.g. [dudect](https://github.com/oreparaz/dudect)-style leakage detection)
run on fixed hardware with load isolated from other processes — a unit test
that calls a function and inspects its return value cannot detect a timing
leak. This is real, valuable future work, not something this pass fakes with
a test that merely calls the function twice and calls it "constant-time
verification."

## Authorized-use note for network scanning (planned Phase 3)

When TLS/SSH PQC scanning lands, only point it at hosts you own or are
explicitly authorized to test. The CLI's `scan` subcommand documentation and
examples should default to `localhost`/owned test infrastructure, not
arbitrary third-party domains.
