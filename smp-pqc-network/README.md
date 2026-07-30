# smp-pqc-network

TLS and SSH handshake scanning for post-quantum/hybrid key-exchange
support.

- `scan::scan_tls` / `scan::scan_tls_insecure` — TLS 1.3, via rustls 0.23's
  native ML-KEM/hybrid support (the `aws-lc-rs` crypto provider).
- `ssh::scan_ssh` — SSH transport handshake, via `russh` 0.62's native
  `mlkem768x25519-sha256` hybrid KEX support.

Both report the *actually negotiated* algorithm, not just what was
offered — the point is catching a hybrid handshake that silently falls
back to its classical leg. **Only scan hosts you own or are explicitly
authorized to test.**

```rust,no_run
use smp_pqc_network::scan::scan_tls;
use std::time::Duration;

let report = scan_tls("example.com", 443, Duration::from_secs(10));
println!("{report:#?}");
```

See the
[project README](https://github.com/rwilliamspbg-ops/smp-pqc-testkit) and
`docs/threat-model.md` for the full `smp-pqc-testkit` workspace, scope
limitations (SSH doesn't verify host identity; no local test-server
coverage for SSH's positive-detection path), and the authorized-use note.

Part of the Sovereign Mohawk PQC Test Kit. Licensed under Apache-2.0.
