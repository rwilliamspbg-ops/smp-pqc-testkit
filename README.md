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

Everything else named in the roadmap below — benchmarking, TLS/SSH scanning,
CBOM inventory, formal verification, TEE attestation — is **not implemented
yet**. Those subcommands exist in the CLI surface but exit with an explicit
"not implemented, planned for Phase N" error rather than faking output.

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
```

Supported `test kem` algorithms: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`.

Supported `test sig` algorithms: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, and all
12 SLH-DSA FIPS-205 parameter sets (`slh-dsa-{shake,sha2}-{128,192,256}{f,s}`).

## Architecture

```
smp-pqc-testkit/
├── smp-pqc-core/     # Safe abstractions over ML-KEM/ML-DSA/SLH-DSA + hybrids
├── smp-pqc-cli/      # smp-pqc binary
├── test-vectors/      # (planned) NIST ACVP KATs
├── docs/               # Threat model, architecture notes
└── examples/           # (planned) Mohawk-Nexus / SMIP-MWP-Rust integration demos
```

Crates not yet created (`smp-pqc-bench`, `smp-pqc-network`, `smp-pqc-tee`,
`smp-pqc-inventory`, `smp-pqc-verify`) will be split out of the workspace when
their phase of work actually starts, rather than scaffolded empty up front.

## Roadmap

See [docs/threat-model.md](docs/threat-model.md) for the threat model this
kit is designed against, and the phase breakdown for what's planned next.
Network scanning, AF_XDP benchmarking, TEE attestation, and formal
verification are all Linux/hardware-dependent or research-scope efforts — see
the threat model doc for realistic sequencing and platform requirements.

## License

Apache-2.0 — see [LICENSE](LICENSE).
