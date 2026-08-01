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
  defeating the point of implicit rejection. Mitigation: DudeCT-based
  constant-time checks across all three ML-KEM parameter sets
  (`smp-pqc-core/examples/dudect_ml_kem*_decap.rs`), plus ML-DSA/SLH-DSA
  signing and the hybrid combiner — see the side-channel section below
  for the measured results and their limits.

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

**This section was stale relative to the code for a while** -- it used to
describe only the original ML-KEM-768 check, but five more checks were
added in the 0.2.0 release (`dudect_ml_kem_512_decap.rs`,
`dudect_ml_kem_1024_decap.rs`, `dudect_ml_dsa_sign.rs`,
`dudect_slh_dsa_sign.rs`, `dudect_hybrid_kem.rs`) and this doc never got
updated to match. Corrected here; see `docs/benchmarks.md` for the full
measured-result table from the run that caught this drift.

All six checks use the [DudeCT](https://eprint.iacr.org/2016/1123.pdf)
statistical methodology via the
[`dudect-bencher`](https://crates.io/crates/dudect-bencher) crate. Run any
of them with `cargo run -p smp-pqc-core --release --example <name>` (or
`just dudect <name>`):

- `dudect_ml_kem_decap.rs` / `dudect_ml_kem_512_decap.rs` /
  `dudect_ml_kem_1024_decap.rs`: whether ML-KEM-{512,768,1024}
  decapsulation timing depends on ciphertext validity — the specific
  concern behind implicit rejection (see `smp-pqc-core/src/kem.rs`'s
  module docs). `Left` = valid ciphertext, `Right` = single flipped bit
  at a random offset.
- `dudect_ml_dsa_sign.rs`: whether ML-DSA-65's retry count under
  Fiat-Shamir-with-aborts rejection sampling depends on the *secret key*
  rather than just public randomness (fixed key/message, varying RNG
  seed) — the retries themselves are expected and not a vulnerability by
  design; a secret-key-dependent retry *count* would be.
- `dudect_slh_dsa_sign.rs`: same question for SLH-DSA-SHA2-128f's
  hash-tree signing (fixed key/message, varying the 32-byte randomizer).
- `dudect_hybrid_kem.rs`: whether the X25519+ML-KEM-768 hybrid combiner's
  control flow (`if classical_ok && pq_ok { combine } `) leaks which leg
  failed through timing.

**Measured results** (this project's Windows dev machine, `--release`,
one run per check, ~11k-20k samples each — see `docs/benchmarks.md` for
the exact numbers and hardware/OS/rustc specs): every check's `max t`
stayed under 2.0 in absolute value, well under the `t > 5` threshold
DudeCT's own docs describe as a good indication of non-constant-time
behavior. **No timing leak was detected** in any of the six checks under
this input distribution, on this machine, as of this run. The original
ML-KEM-768 check has additional history behind it: three independent
20,000-sample runs plus one ~20-second `--continuous` run accumulating
300,000+ samples, all consistently in the 1.3-2.7 range.

Read these results correctly:
- This is evidence of *no detected* leak, not a proof of constant-time-ness
  in general — DudeCT's own README says exactly this: "it is not possible
  to prove that a function always runs in constant time."
- The measurement environment matters. These ran on a general-purpose
  Windows dev machine, not a quiet, CPU-pinned, frequency-scaling-disabled
  benchmark rig. That's an argument for the *low* t-values being credible
  (noise pushes t-values around, and they stayed low anyway) — but it also
  means a marginal real leak close to the noise floor could still be
  masked. Take these as real, reassuring first checks, not a certified
  clean bill of health.
- Coverage is now six operations across ML-KEM (all three parameter
  sets' decapsulation), ML-DSA (one parameter set's signing), SLH-DSA (one
  of twelve parameter sets' signing), and the hybrid combiner — still not
  exhaustive (ML-DSA-44/87 and the other eleven SLH-DSA parameter sets
  aren't covered yet), but broader than "one operation" now. Extending
  further is mechanical (the existing checks are templates), not blocked
  on anything new.
- Not wired into CI: shared CI runners are virtualized, multi-tenant, and
  have no CPU pinning, which is exactly the kind of environment that
  produces false-positive timing differences from noise, not genuine leaks.
  These are manual/local diagnostic tools, run deliberately on a quiet
  machine, not an automated gate.

## Supply-chain / dependency advisories

`cargo deny check` (`deny.toml`, `cargo-deny` CI job) gates every dependency
against the RustSec advisory database, license compliance, and unexpected
registries/git sources on every push. Three advisories are explicitly
ignored rather than silently passing:

- **RUSTSEC-2021-0139** (`ansi_term` unmaintained) and **RUSTSEC-2024-0375**
  (`atty` unmaintained): both pulled in only via `dudect-bencher` (a
  dev-dependency of `smp-pqc-core`'s constant-time-check examples) ->
  `clap 2.34.0`. Dev-dependencies never appear in a published crate's
  manifest, so this never reaches anyone depending on `smp-pqc-core` from
  crates.io -- it only affects building/testing this workspace directly.
  No safe upgrade exists (dudect-bencher 0.7.0 is the latest release and
  still pins clap 2).
- **RUSTSEC-2023-0071** (`rsa` "Marvin Attack" timing side-channel): pulled
  in transitively via `smp-pqc-network`'s *non-dev* dependency on
  `russh`/`ssh-key` (SSH RSA host-key and signature support). No safe
  upgrade is available upstream. `scan ssh` is a client that never holds
  or exercises its own RSA private key -- it only verifies signatures the
  remote host presents using the host's public key, so the exploitable
  path (private-key timing leakage during decrypt/sign) isn't reachable
  through this crate's use of `russh`. This is a real, tracked risk for
  anyone who builds a different, key-holding use of `russh`/`rsa` on top
  of `smp-pqc-network`, though -- it is not eliminated, only not currently
  exercised by this crate's own code. Revisit when RustCrypto/RSA ships a
  constant-time fix.

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
