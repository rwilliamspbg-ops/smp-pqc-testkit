# smp-pqc-core

Safe Rust abstractions over NIST post-quantum cryptography — FIPS 203
ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA (via the pure-Rust
[RustCrypto](https://github.com/RustCrypto) `ml-kem`/`ml-dsa`/`slh-dsa`
crates) — plus an illustrative X25519 + ML-KEM-768 classical/PQC hybrid
KEM.

```rust
use smp_pqc_core::kem;

let report = kem::run(kem::KemAlgorithm::MlKem768, 100);
assert!(report.all_passed());
```

See [`examples/basic_usage.rs`](examples/basic_usage.rs) for a fuller
example, and the
[project README](https://github.com/rwilliamspbg-ops/smp-pqc-testkit) for
the full `smp-pqc-testkit` workspace this crate is part of (CLI,
benchmarks, network scanning, cryptography inventory, and NIST ACVP
known-answer tests validating this crate against real reference vectors).

Part of the Sovereign Mohawk PQC Test Kit. Licensed under Apache-2.0.
