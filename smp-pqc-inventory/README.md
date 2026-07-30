# smp-pqc-inventory

Scans a `Cargo.lock`, classifies known crypto crates against a curated
table (PQC vs. classical, and by primitive — KEM, signature, cipher, hash,
MAC, protocol, RNG, or supporting utility), and emits either a
human-readable summary or a CycloneDX-shaped cryptography bill of
materials (CBOM).

```rust,no_run
use smp_pqc_inventory::{cbom, classify, lockfile};
use std::path::Path;

let path = lockfile::resolve_lockfile_path(Path::new(".")).unwrap();
let packages = lockfile::parse_lockfile(&path).unwrap();
let document = cbom::build_cbom(&packages);
println!("{}", serde_json::to_string_pretty(&document).unwrap());
```

Classification is a curated, name-based lookup table, not static analysis
of actual code usage — see the honesty note in `src/classify.rs` for
exactly what that does and doesn't mean.

See the
[project README](https://github.com/rwilliamspbg-ops/smp-pqc-testkit) for
the `smp-pqc inventory`/`inventory --cbom` CLI commands and the full
`smp-pqc-testkit` workspace.

Part of the Sovereign Mohawk PQC Test Kit. Licensed under Apache-2.0.
