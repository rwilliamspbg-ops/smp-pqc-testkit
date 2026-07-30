# examples/

This directory is reserved for **Mohawk-Nexus / SMIP-MWP-Rust integration demos** -- worked examples of wiring `smp-pqc-testkit` into those specific downstream projects.

For a working example of using `smp-pqc-core` as a plain Rust library (independent of any specific downstream project), see
[`smp-pqc-core/examples/basic_usage.rs`](../smp-pqc-core/examples/basic_usage.rs):

```bash
cargo run -p smp-pqc-core --example basic_usage
```

## Integration Examples

This directory contains example integrations with the Mohawk-Nexus and SMIP-MWP-Rust stacks. These examples are intended to illustrate how the SMP-PQC-Testkit can be used in the context of those projects.

To run these examples, you will need to have the Mohawk-Nexus and/or SMIP-MWP-Rust dependencies available. Since those are separate projects, you may need to adjust the dependencies in the example files or create a temporary Cargo.toml in this directory.

### Mohawk-Nexus Integration

See `mohawk_nexus_integration.rs` for an example of using SMP-PQC-Testkit to establish a post-quantum secure connection in a Mohawk-Nexus networking stack.

### SMIP-MWP-Rust Integration

See `smip_mwp_rust_integration.rs` for an example of using SMP-PQC-Testkit to sign and verify messages in a SMIP-MWP-Rust secure multiparty computation workflow.

## Running the Examples

Each example is a standalone Rust file. To compile and run an example:

1. Ensure you have built the workspace dependencies:
   ```bash
   cd /path/to/smp-pqc-testkit
   cargo build --workspace
   ```

2. Compile the example, linking against the built `smp-pqc-core` library:
   ```bash
   rustc --extern smp_pqc_core=target/debug/libsmp_pqc_core.rlib examples/mohawk_nexus_integration.rs
   ```

3. Run the resulting executable:
   ```bash
   ./mohawk_nexus_integration
   ```

Note: These examples may require additional dependencies from the Mohawk-Nexus or SMIP-MWP-Rust projects. Consult those projects' documentation for setup instructions.

## TODO

- [ ] Add actual Mohawk-Nexus and SMIP-MWP-Rust dependencies when available
- [ ] Convert examples to proper Cargo examples with a Cargo.toml in this directory
- [ ] Add more comprehensive examples showing full integration workflows