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
  `smp-pqc-core/test-vectors/SOURCE.md` for exact scope.
- **Downgrade attacks**: a hybrid handshake that silently falls back to the
  classical leg alone. Mitigation: `smp-pqc-network`'s TLS scanner
  (`scan tls`) and SSH scanner (`scan ssh`) both report the actual
  negotiated key-exchange algorithm, not just what was offered. QUIC
  scanning is still planned, not implemented.
- **Supply-chain drift**: unaudited or unmaintained crypto dependencies pulled
  into a downstream project. Mitigation: `smp-pqc-inventory` generates a
  CycloneDX-style cryptography bill of materials (CBOM) so downstream
  consumers know exactly which crypto crates, versions, and PQC/classical
  classifications are in use.
- **Decapsulation timing oracle**: an adversary measuring how long
  decapsulation takes to distinguish valid from corrupted ciphertexts,
  defeating the point of implicit rejection. Mitigation: a DudeCT-based
  constant-time check (`smp-pqc-core/examples/dudect_ml_kem_decap.rs`) — see
  the side-channel section below for the measured result and its limits.

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
- **SSH PQC scanning** (`scan ssh`) is implemented. `russh` 0.62.4's
  `Handler::kex_done` callback exposes the negotiated `Names` (including
  `names.kex`) directly — the earlier note in this doc about the
  negotiated-algorithm value possibly not being exposed on the public API
  was overly pessimistic from a first pass; a deeper look found the right
  hook. Runs its own single-threaded Tokio runtime internally (the rest of
  this CLI is synchronous). Does not verify host identity — accepts any
  server host key, since there's no CA/root-of-trust equivalent for SSH the
  way `webpki-roots` provides for TLS; treat results as informational about
  what a host offers, not an authenticated connection. Manually verified
  against `github.com`'s real SSH endpoint: negotiated `curve25519-sha256`
  (github.com does not currently offer the hybrid PQC KEX), correctly
  reported as non-PQC. No local test-server coverage for the positive
  PQC-detection path (unlike `scan tls`) — `russh`'s server API would need
  a full handler (host key, auth) to stand one up, not attempted this pass.
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

## Side-channel / constant-time testing

**One targeted check exists; broad coverage does not.**
`smp-pqc-core/examples/dudect_ml_kem_decap.rs` uses the
[DudeCT](https://eprint.iacr.org/2016/1123.pdf) statistical methodology
(via the [`dudect-bencher`](https://crates.io/crates/dudect-bencher) crate)
to test whether ML-KEM-768's decapsulation timing depends on ciphertext
validity — the specific concern behind implicit rejection (see
`smp-pqc-core/src/kem.rs`'s module docs). Run it yourself:

```bash
cargo run -p smp-pqc-core --release --example dudect_ml_kem_decap
```

**Measured result** (this project's Windows dev machine, `--release`,
20,000 samples per run, three independent runs plus one ~20-second
`--continuous` run accumulating 300,000+ samples): `max t` consistently
stayed between 1.3 and 2.7 in absolute value, well under the t > 5 threshold
DudeCT's own docs describe as a good indication of non-constant-time
behavior. **No timing leak was detected** under this input distribution, on
this machine, as of this test's addition.

Read that result correctly:
- This is evidence of *no detected* leak, not a proof of constant-time-ness
  in general — DudeCT's own README says exactly this: "it is not possible
  to prove that a function always runs in constant time."
- The measurement environment matters. This ran on a general-purpose
  Windows dev machine, not a quiet, CPU-pinned, frequency-scaling-disabled
  benchmark rig. That's an argument for the *low* t-values being credible
  (noise pushes t-values around, and it stayed low anyway across repeated
  runs and rising sample counts) — but it also means a marginal real leak
  close to the noise floor could still be masked. Take this as a real,
  reassuring first check, not a certified clean bill of health.
- This covers exactly one operation (ML-KEM-768 decapsulate, one
  corruption pattern: a single flipped byte at a random offset). It says
  nothing about ML-KEM-512/1024, ML-DSA, or SLH-DSA's sign/verify timing —
  extending this to signatures needs care: ML-DSA's Fiat-Shamir-with-aborts
  rejection sampling causes *expected* variable-time behavior that isn't
  itself a vulnerability (unless the retry count depends on the secret key
  in an exploitable way), and distinguishing "expected variance from public
  randomness" from "a real secret-dependent leak" needs more care than a
  first pass gives it credit for. Left as explicit future work rather than
  risking a misleading interpretation.
- Not wired into CI: shared CI runners are virtualized, multi-tenant, and
  have no CPU pinning, which is exactly the kind of environment that
  produces false-positive timing differences from noise, not genuine leaks.
  This is a manual/local diagnostic tool, run deliberately on a quiet
  machine, not an automated gate.

## Authorized-use note for network scanning

`smp-pqc-network`'s TLS scanner (`smp-pqc scan tls <host>`) and SSH scanner
(`smp-pqc scan ssh <host>`) are both implemented. Only point them at hosts
you own or are explicitly authorized to test. There is no default host —
the CLI always requires one to be specified explicitly. The TLS scanner's
test suite only ever scans a local rustls server it spins up itself, never
an external host; the SSH scanner's automated tests are limited to the
unreachable-host error path for the same reason (no local test-server
coverage yet — see the SSH note under Platform constraints). QUIC scanning
is still planned, not implemented; the same authorized-use expectation will
apply when it lands.
