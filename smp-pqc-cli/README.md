# smp-pqc-cli

The `smp-pqc` command-line binary for the Sovereign Mohawk PQC Test Kit:
NIST post-quantum cryptography (FIPS 203/204/205) correctness testing, TLS
and SSH PQC/hybrid handshake scanning, and cryptography inventory / CBOM
generation.

```bash
cargo install smp-pqc-cli

smp-pqc test kem ml-kem-768 --iterations 10000
smp-pqc test sig ml-dsa-65 --iterations 1000
smp-pqc scan tls example.com --pqc-only
smp-pqc scan ssh example.com
smp-pqc inventory . --cbom
```

Only scan hosts you own or are explicitly authorized to test.

See the [project README](https://github.com/rwilliamspbg-ops/smp-pqc-testkit)
for the full `smp-pqc-testkit` workspace, what's actually implemented vs.
still in progress, and the threat model this kit is designed against.

Part of the Sovereign Mohawk PQC Test Kit. Licensed under Apache-2.0.
