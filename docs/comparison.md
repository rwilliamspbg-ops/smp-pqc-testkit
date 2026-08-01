# Comparison: smp-pqc-testkit vs. liboqs / PQClean

This is an honest comparison, not a sales pitch — the goal is to help
someone pick the right tool, including picking something else when that's
the right call. See [ROADMAP.md](ROADMAP.md) for why this project
deliberately doesn't try to match liboqs on algorithm breadth.

**Important scope note**: smp-pqc-testkit doesn't implement PQC algorithms
from scratch. It wraps the pure-Rust RustCrypto crates (`ml-kem`, `ml-dsa`,
`slh-dsa`) and adds test/validation/scanning/inventory tooling around
them. liboqs and PQClean *are* the algorithm implementations (in C). This
means smp-pqc-testkit's correctness claims are about its wrapper logic and
about validating RustCrypto's output against NIST's ACVP vectors — not
about having independently implemented and audited the underlying lattice
math, which RustCrypto and NIST's ACVP process are responsible for.

| | smp-pqc-testkit | liboqs | PQClean |
|---|---|---|---|
| What it is | Test/validation/scanning kit built on existing Rust crypto crates | The algorithm implementations themselves, in C | The algorithm implementations themselves, in C (reference/portable) |
| Language | Rust (memory-safe; underlying algorithms via RustCrypto, also pure Rust) | C | C |
| Algorithm breadth | ML-KEM, ML-DSA, SLH-DSA (all standardized FIPS 203/204/205 parameter sets) | ML-KEM, ML-DSA, SLH-DSA, Falcon (draft FN-DSA), Classic McEliece, BIKE, HQC, and more | Similar breadth to liboqs (liboqs vendors much of its code from here) |
| NIST ACVP known-answer tests against real reference vectors | Yes (`smp-pqc-core/tests/acvp.rs`) | Not a primary focus of the project itself | Not a primary focus of the project itself |
| Real network handshake scanning (TLS/SSH/QUIC) reporting actually-negotiated algorithms | Yes (`smp-pqc-network`) | No — that's out of scope for a crypto library | No |
| Cryptography inventory / CBOM generation from a dependency tree | Yes (`smp-pqc-inventory`) | No | No |
| Formal verification | Lean 4 proofs of this project's own control-flow logic (hybrid combiner, report aggregation) — not the primitives themselves | No (relies on the primitive-level guarantees of whatever's vendored in) | No |
| Constant-time / side-channel testing | One targeted DudeCT check (ML-KEM-768 decapsulation), expanding — see threat model | Some internal timing-safety engineering practice, not a public test harness in this form | Reference implementations aim for constant-time by construction; no public per-build test harness |
| Language bindings | Rust only | C, with bindings for Python, Go, Java, .NET, Rust (`oqs` crate), and more | C, consumed by liboqs and others |
| Maturity / adoption | New (this is the 1.0.0 release) | Mature, widely deployed, used by OpenSSL/BoringSSL forks and major vendors | Mature, foundational to the above |
| Best fit | Validating a Rust project's PQC posture: correctness, real handshake behavior, dependency inventory, in a memory-safe stack | Need broad algorithm coverage, cross-language bindings, or a battle-tested C implementation | Need a minimal, portable reference implementation to vendor into your own project |

## When to reach for something else

- Need Falcon, Classic McEliece, BIKE, or HQC today: use liboqs (directly,
  or via the `oqs` Rust crate).
- Need bindings outside Rust: use liboqs.
- Building a new C/embedded PQC implementation from scratch: start from
  PQClean's reference code, not this project.
- Need a from-scratch, audited-from-zero implementation of the lattice
  math itself: none of these three provide that on their own — that's
  what NIST's ACVP validation program and academic cryptanalysis are for.

## When this project is the right fit

- You're building on the RustCrypto ecosystem already and want confidence
  that ML-KEM/ML-DSA/SLH-DSA are wired correctly, validated against real
  NIST vectors, not just "it compiles and round-trips."
- You need to know what a TLS/SSH endpoint *actually* negotiated, not
  just what it advertises supporting (catching a hybrid handshake that
  silently falls back to its classical leg).
- You need a cryptography inventory (CBOM) for a Rust dependency tree,
  classified PQC vs. classical.
- You want a test kit that's explicit about what it hasn't verified yet,
  rather than one that implies more coverage than it has.
