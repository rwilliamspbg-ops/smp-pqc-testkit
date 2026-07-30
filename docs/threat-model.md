# Threat model

## What this kit defends against

- **Harvest-now-decrypt-later**: an adversary recording classically-encrypted
  traffic today, to decrypt once a cryptographically relevant quantum computer
  (CRQC) exists. Mitigation: verify PQC/hybrid key exchange is actually
  negotiated and correct, not just configured.
- **Broken or non-conformant PQC implementations**: a library that claims
  FIPS 203/204/205 support but has a subtly wrong encoding, an RNG misuse, or
  fails on edge-case parameter sets. Mitigation: roundtrip + tamper-detection
  tests across all standardized parameter sets, and NIST ACVP known-answer
  tests against real reference vectors (`smp-pqc-core/tests/acvp.rs`) — see
  `test-vectors/acvp/SOURCE.md` for exact scope.
- **Downgrade attacks**: a hybrid handshake that silently falls back to the
  classical leg alone. Mitigation: `smp-pqc-network`'s TLS scanner
  (`scan tls`) reports the actual negotiated key-exchange group, not just
  what was offered. SSH/QUIC scanning is still planned, not implemented (see
  the SSH note under Platform constraints below for what's actually blocking
  it — it isn't a missing algorithm).
- **Supply-chain drift**: unaudited or unmaintained crypto dependencies pulled
  into a downstream project. Mitigation: `smp-pqc-inventory` generates a
  CycloneDX-style cryptography bill of materials (CBOM) so downstream
  consumers know exactly which crypto crates, versions, and PQC/classical
  classifications are in use.

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
  Linux kernel with XDP/eBPF support *and* a NIC driver that supports XDP
  offload. WSL2 has the former (a real, modern kernel with BTF support) but
  not the latter: its virtual NIC uses the `hv_netvsc` Hyper-V synthetic
  driver, which only supports AF_XDP's generic/SKB software-emulation mode,
  not true zero-copy. Building "zero-copy benchmarking" on that foundation
  would silently misrepresent the result, so this stays unimplemented until
  there's access to bare-metal Linux with an XDP-capable NIC (e.g. mlx5,
  i40e, ixgbe) — WSL2 alone does not unblock this.
- **TEE attestation** (planned `smp-pqc-tee`) requires TEE-capable hardware
  (Intel SGX, AMD SEV, Arm TrustZone) with direct enclave/hardware passthrough.
  A standard WSL2 VM doesn't expose this either — same category of blocker as
  AF_XDP above, and for the same reason: virtualization gets you a real Linux
  kernel, not real hardware capabilities the kernel would otherwise expose.
- **TPM access** depends on OS/hardware TPM availability; the `tss-esapi`
  crate (not `tpm2-rs`, which does not appear to exist under that name — this
  was corrected from an earlier draft of the plan) is the maintained Rust TSS
  binding to evaluate here.
- **SSH PQC scanning** is not blocked by algorithm support: `russh` 0.62.4
  already implements `mlkem768x25519-sha256` hybrid KEX
  (`russh::kex::MLKEM768X25519_SHA256`), matching what OpenSSH 9.x+ offers.
  What's actually missing is the integration work: `russh`'s client API is
  async (tokio) where the rest of this CLI is synchronous, and the
  negotiated-algorithm value (`negotiation::Names.kex`) wasn't confirmed to
  be exposed on the public `Handle`/`Session` type during a first pass —
  it may require a custom `Handler` callback or additional API spelunking.
  Deferred rather than rushed; this is genuinely tractable, just not a
  quick addition alongside everything else in this pass.
- **Formal verification** (`smp-pqc-verify`): proving PQC primitives from
  scratch is a research-scale effort, out of scope here — this project cites
  [libcrux](https://github.com/cryspen/libcrux)'s existing HACL*-derived
  proofs for that instead. What's actually implemented: `smp-pqc-verify` is
  a Lean 4 project (not TLA+ — no Java/TLC toolchain was available in this
  environment, and building an "unverified TLA+ spec" would be the same
  category of problem as faking AF_XDP zero-copy on WSL2's `hv_netvsc`
  driver: claiming a check that never actually ran) with real,
  machine-checked, `sorry`-free proofs about `smp-pqc-core`'s control-flow
  logic — the hybrid KEM combiner and the signature-report aggregation
  accounting — not about the underlying lattice/hash math. See
  `smp-pqc-verify/README.md` for exactly what's proved and what isn't.
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

## Authorized-use note for network scanning

`smp-pqc-network`'s TLS scanner (`smp-pqc scan tls <host>`) is implemented.
Only point it at hosts you own or are explicitly authorized to test. There
is no default host — the CLI always requires one to be specified explicitly
— and the crate's own test suite only ever scans a local rustls server it
spins up itself, never an external host, so CI never depends on (or
inadvertently scans) third-party infrastructure. SSH/QUIC scanning is still
planned, not implemented; the same authorized-use expectation will apply
when it lands.
