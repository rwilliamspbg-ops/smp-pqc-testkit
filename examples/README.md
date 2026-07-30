# examples/

This directory is reserved for **Mohawk-Nexus / SMIP-MWP-Rust integration
demos** -- worked examples of wiring `smp-pqc-testkit` into those specific
downstream projects. It's still empty: those are separate projects this kit
is meant to integrate with, and a real integration demo needs their actual
APIs to write against honestly, not a guess at what they might look like.

For a working example of using `smp-pqc-core` as a plain Rust library
(independent of any specific downstream project), see
[`smp-pqc-core/examples/basic_usage.rs`](../smp-pqc-core/examples/basic_usage.rs):

```bash
cargo run -p smp-pqc-core --example basic_usage
```
