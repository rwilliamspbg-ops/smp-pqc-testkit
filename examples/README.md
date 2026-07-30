# examples/

This directory contains example integrations with the Mohawk-Nexus and SMIP-MWP-Rust stacks.
These examples demonstrate how to use `smp-pqc-testkit` in the context of those projects.

## Examples

### Mohawk-Nexus Integration

See `mohawk_nexus_integration.rs` for an example of using SMP-PQC-Testkit to establish
post-quantum secure connections in a Mohawk-Nexus networking stack.

To run:
```bash
cargo run -p smp-pqc-core --example mohawk_nexus_integration
```

### SMIP-MWP-Rust Integration

See `smip_mwp_integration.rs` for an example of using SMP-PQC-Testkit to sign and verify
shares in a SMIP-MWP-Rust secure multiparty computation workflow.

To run:
```bash
cargo run -p smp-pqc-core --example smip_mwp_integration
```

## Basic Library Usage

For a simple example of using `smp-pqc-core` as a library (independent of any specific
downstream project), see [`smp-pqc-core/examples/basic_usage.rs`](../smp-pqc-core/examples/basic_usage.rs):

```bash
cargo run -p smp-pqc-core --example basic_usage
```

## Constant-Time Testing

See also the constant-time checking example:
[`smp-pqc-core/examples/dudect_ml_kem_decap.rs`](../smp-pqc-core/examples/dudect_ml_kem_decap.rs):

```bash
cargo run -p smp-pqc-core --release --example dudect_ml_kem_decap
```