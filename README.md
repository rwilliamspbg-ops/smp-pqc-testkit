# smp-pqc-testkit

```
   _____ __  __ _____    _____   ____   _____
  / ____|  \/  |  __ \  |  __ \ / __ \ / ____|
 | (___ | \  / | |__) | | |__) | |  | | |
  \___ \| |\/| |  ___/  |  ___/| |  | | |
  ____) | |  | | |      | |    | |__| | |____
 |_____/|_|  |_|_|      |_|     \____/ \_____|

 Sovereign Mohawk Post-Quantum Cryptography Test Kit
```

A Rust workspace for testing NIST post-quantum cryptography (FIPS 203 ML-KEM,
FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and classical/PQC hybrids, built as a
component for the Mohawk-Nexus / SMIP-MWP-Rust / smp-tee-runtime /
Sovereign-Mohawk-Proto stack.

## Status

Early scaffold. What actually works today:

- `smp-pqc-core`: safe wrappers over [`ml-kem`](https://crates.io/crates/ml-kem),
  [`ml-dsa`](https://crates.io/crates/ml-dsa), and [`slh-dsa`](https://crates.io/crates/slh-dsa)
  (all pure-Rust RustCrypto implementations), plus an illustrative
  X25519 + ML-KEM-768 hybrid KEM.
- `smp-pqc-cli` (`smp-pqc` binary): `test kem` and `test sig` subcommands run
  real correctness roundtrips (keygen/encapsulate-or-sign/decapsulate-or-verify,
  including tamper-detection checks for signatures).
- `smp-pqc-bench`: real Criterion benchmarks for keygen/encapsulate/decapsulate
  and keygen/sign/verify across every ML-KEM/ML-DSA/SLH-DSA parameter set,
  plus an X25519 classical baseline for comparison.
- Test suite: 95.9% line coverage / 100% function coverage across
  `smp-pqc-core` + `smp-pqc-cli` (measured with `cargo llvm-cov`, not
  asserted), including proptest-based property tests (arbitrary-message
  signing, single-byte ciphertext/message tamper rejection across randomized
  offsets), adversarial tests (wrong keys, corrupted signature/ciphertext
  bytes, ML-KEM implicit rejection), and CLI-level integration tests via
  `assert_cmd`.
- `smp-pqc-core/fuzz`: a `cargo-fuzz` target for the algorithm-name parsers.
  Narrow in scope (there's no byte-serialization API to fuzz yet — see
  [docs/threat-model.md](docs/threat-model.md)) and Linux-only in practice;
  runs in CI, not on this project's Windows dev machine.
- `test-vectors/acvp` + `smp-pqc-core/tests/acvp.rs`: KAT smoke tests against
  NIST's own ACVP-Server reference vectors (ML-KEM keygen + decapsulation
  including NIST's own implicit-rejection cases; ML-DSA/SLH-DSA keygen; ML-DSA/
  SLH-DSA signature verification including deliberately-corrupted negative
  cases, with context strings). This validates the underlying RustCrypto
  crates against NIST's ground truth, not just internal self-consistency —
  see [test-vectors/acvp/SOURCE.md](test-vectors/acvp/SOURCE.md) for exactly
  what's covered and what isn't (no prehash mode, no ML-KEM encapsulation
  direction yet).

Everything else named in the roadmap below — TLS/SSH scanning, CBOM
inventory, formal verification, TEE attestation, AF_XDP benchmarking,
side-channel/constant-time analysis — is **not implemented yet**. The
relevant CLI subcommands exist but exit with an explicit "not implemented,
planned for Phase N" error rather than faking output; see
[docs/threat-model.md](docs/threat-model.md) for why each of these is
harder than it looks and what real scope looks like.

## Usage

```bash
cargo build --workspace

# KEM roundtrip correctness test
cargo run -p smp-pqc-cli -- test kem ml-kem-768 --iterations 10000

# Classical/PQC hybrid KEM
cargo run -p smp-pqc-cli -- test kem ml-kem-768 --hybrid --iterations 1000

# Signature roundtrip + tamper-detection test
cargo run -p smp-pqc-cli -- test sig ml-dsa-65 --iterations 1000
cargo run -p smp-pqc-cli -- test sig slh-dsa-shake-128f --iterations 20 --report json

# Criterion benchmarks (release mode; several minutes for the full suite due
# to slow SLH-DSA "s" variants -- see smp-pqc-bench/benches/sig.rs)
cargo bench -p smp-pqc-bench --bench kem
cargo bench -p smp-pqc-bench --bench sig

# Run the test suite, including NIST ACVP KAT checks (takes ~100-110s:
# SLH-DSA-256s alone is ~1-2 min/sign in an unoptimized build without the
# workspace's dependency opt-level override -- see Cargo.toml and
# smp-pqc-core/src/sig.rs for why)
cargo test --workspace
```

Supported `test kem` algorithms: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`.

Supported `test sig` algorithms: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, and all
12 SLH-DSA FIPS-205 parameter sets (`slh-dsa-{shake,sha2}-{128,192,256}{f,s}`).

## Architecture

```
smp-pqc-testkit/
├── smp-pqc-core/     # Safe abstractions over ML-KEM/ML-DSA/SLH-DSA + hybrids
│   └── fuzz/           # cargo-fuzz target for the algorithm-name parsers (Linux-only)
├── smp-pqc-cli/      # smp-pqc binary
├── smp-pqc-bench/    # Criterion benchmarks (keygen/encap/decap, keygen/sign/verify)
├── test-vectors/acvp/ # Sampled NIST ACVP-Server reference vectors + provenance (SOURCE.md)
├── docs/               # Threat model, architecture notes
└── examples/           # (planned) Mohawk-Nexus / SMIP-MWP-Rust integration demos
```

Crates not yet created (`smp-pqc-network`, `smp-pqc-tee`, `smp-pqc-inventory`,
`smp-pqc-verify`) will be split out of the workspace when their phase of work
actually starts, rather than scaffolded empty up front.

## Roadmap

See [docs/threat-model.md](docs/threat-model.md) for the threat model this
kit is designed against, and the phase breakdown for what's planned next.
Network scanning, AF_XDP benchmarking, TEE attestation, and formal
verification are all Linux/hardware-dependent or research-scope efforts — see
the threat model doc for realistic sequencing and platform requirements.

## License

Apache-2.0 — see [LICENSE](LICENSE).
