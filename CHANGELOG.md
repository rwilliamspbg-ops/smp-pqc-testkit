# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-07-31

First stable release. No breaking API changes from 0.2.0 -- this release is
about hardening the release process and developer experience around the
functionality 0.2.0 already shipped, not new cryptographic surface.

### Added

- **Enforced coverage thresholds**: the `coverage` CI job now actually fails
  the build below a real floor instead of just generating a report nobody
  gates on. Split into two per-crate checks (`smp-pqc-core` >= 90% lines/
  functions, `smp-pqc-cli` >= 60%) rather than one combined threshold,
  because the two crates are at very different coverage levels -- see the
  "Fixed" section below for the corrected README claim this replaces.
- **Pinned MSRV** (`rust-version = "1.88.0"` in `[workspace.package]`),
  verified locally (`cargo +1.88.0 build/test --workspace --all-targets
  --locked`) and checked on every push via a new `msrv` CI job. The floor is
  set by `criterion`/`time`'s own MSRV, not this workspace's code.
- **`cargo-deny` supply-chain gate** (`deny.toml`, `cargo-deny` CI job):
  checks every dependency against the RustSec advisory database, license
  compliance, and unexpected registries/git sources on every push. Three
  advisories are explicitly ignored with documented justification (two
  dev-only-via-`dudect-bencher` unmaintained-crate advisories that never
  reach a published crate's dependency graph; one transitive `rsa` timing
  side-channel advisory via `russh`/`ssh-key` that isn't exploitable through
  `scan ssh`'s client-only usage) -- see `docs/threat-model.md`'s new
  "Supply-chain / dependency advisories" section.
- **GitHub contributor scaffolding**: bug report / feature request issue
  templates (`.github/ISSUE_TEMPLATE/`), a PR template
  (`.github/PULL_REQUEST_TEMPLATE.md`), and `CODEOWNERS`.
- **`justfile`**: wraps the common dev commands (`build`, `test`, `fmt`,
  `clippy`, `doc`, `deny`, `coverage`, `msrv`, `fuzz`, `lean`, `dudect`,
  `package-check`, `release-check`) that previously only existed as
  scattered CI/README/RELEASING.md snippets.
- **`.editorconfig`** and an explicit **`rustfmt.toml`** (pins `edition =
  "2021"` for rustfmt's own inference; otherwise all defaults -- verified to
  produce zero formatting diff against the existing tree).
- **README badges**: CI status, Codecov, crates.io version, docs.rs, MSRV,
  license.

### Changed

- **`SECURITY.md`**: replaced the non-functional placeholder email
  (`security@smp-pqc-testkit.example.com`) with GitHub's private
  vulnerability reporting flow, which doesn't require a maintainer email
  inbox at all.
- Bumped `[workspace.package].version` to `1.0.0` (every crate inherits it);
  updated `smp-pqc-cli`'s path-dependency version pins to match.

### Fixed

- **Stack overflow in `smp-pqc test sig`**: the direct `test sig <algo>`
  command path called `sig::run()` on the main thread with no large-stack
  wrapping, unlike `verify-all`'s dedicated 16MB-stack worker thread added
  in 0.2.0. Reproduced a real overflow running `smp-pqc test sig
  ml-dsa-65 --iterations 3 --report json` under rustc 1.88.0 (the default
  toolchain's codegen happened not to trip it, which is why this wasn't
  caught before -- not evidence the bug wasn't there). Extracted a shared
  `run_on_large_stack` helper and applied it to both call sites.
- **Corrected an inflated coverage claim**: the README stated "95%+ line
  coverage / 95%+ function coverage across `smp-pqc-core` + `smp-pqc-cli`",
  which was never true for `smp-pqc-cli` -- measured coverage is ~95%+ for
  `smp-pqc-core` (kem.rs/sig.rs) but only ~60-65% for `smp-pqc-cli`
  (main.rs/config.rs), largely CLI dispatch and config-merge branches that
  need a live host or specific flag combinations to exercise. The README's
  Status section and the CI coverage gate above now both reflect the real,
  split numbers instead of one inflated combined figure.

## [0.2.0] - 2026-07-31

### Added

- **crates.io publishing preparation**: `smp-pqc-core`, `smp-pqc-cli`,
  `smp-pqc-network`, and `smp-pqc-inventory` now have full crates.io
  metadata (`readme`, `keywords`, `categories`, a bundled `LICENSE` copy
  each) and a per-crate `README.md`. `.github/workflows/publish.yml`
  publishes all four automatically on a `vX.Y.Z` tag push, in dependency
  order, once a `CARGO_REGISTRY_TOKEN` repository secret is added -- see
  `RELEASING.md`. A `package-check` CI job runs `cargo package` for the
  three independent crates on every push to catch metadata/packaging
  regressions before they'd ever reach an actual publish attempt.
- **SSH PQC/hybrid KEX scanning** (`scan ssh`, `smp-pqc-network::ssh`): uses
  `russh` 0.62's native `mlkem768x25519-sha256` support and its
  `Handler::kex_done` callback to report the actually negotiated
  key-exchange algorithm. Manually verified against `github.com`'s real SSH
  endpoint (negotiated `curve25519-sha256`, correctly reported as non-PQC).
  Does not verify host identity (accepts any host key). No local
  test-server coverage for the positive-detection path yet, unlike
  `scan tls` -- see `docs/threat-model.md`.
- **Expanded constant-time testing** (DudeCT-based):
  - `dudect_ml_kem_512_decap.rs`: ML-KEM-512 decapsulation valid vs. corrupted ciphertext
  - `dudect_ml_kem_1024_decap.rs`: ML-KEM-1024 decapsulation valid vs. corrupted ciphertext
  - `dudect_ml_dsa_sign.rs`: ML-DSA-65 signing timing (best-effort, limited by crate's internal RNG)
  - `dudect_slh_dsa_sign.rs`: SLH-DSA-SHA2-128f signing with controlled randomizer
  - `dudect_hybrid_kem.rs`: X25519 + ML-KEM-768 hybrid combiner control-flow timing
  - All examples run with `cargo run -p smp-pqc-core --release --example <name>`
- **QUIC scanner stub** (`scan quic`, `smp-pqc-network::quic`): CLI subcommand with clear
  "not yet implemented" error; full implementation using quinn + rustls backend planned for Phase 3.
- **Inventory/CBOM classification table expansion**:
  - Added `quinn`, `quinn-proto` (QUIC protocol, PQC-capable)
  - Added `hpke` (Hybrid PKE, RFC 9180)
  - Added `tss-esapi` (TPM 2.0 TSS binding for TEE attestation)
- **Integration examples verified**: `mohawk_nexus_integration`, `smip_mwp_integration` compile and run.

### Changed

- Updated threat model documentation (`docs/threat-model.md`) with side-channel testing caveats.
- Added `tokio` dependency to `smp-pqc-cli` for QUIC async runtime.
- Added `quinn`, `quinn-proto` dependencies to `smp-pqc-network`.

### Fixed

- All workspace tests pass (73 tests across Rust workspace + Lean 4 proofs).
- Coverage maintained at ~89% (QUIC stub at 0% expected as placeholder).
- Moved `test-vectors/acvp/` (workspace root) to `smp-pqc-core/test-vectors/`
  (inside the crate). `smp-pqc-core/tests/acvp.rs`'s `include_str!` calls
  can only resolve files within the crate's own directory tree; the old
  path worked fine in this workspace but would have failed to compile for
  anyone building `smp-pqc-core` from its published crates.io tarball,
  since `cargo package` doesn't include files from outside the crate
  directory. Caught while preparing crates for publishing, before any
  version was actually published with the bug.
- `smp-pqc-inventory`'s tests read the workspace root's `Cargo.lock` via a
  `../` path for realistic test data — same category of bug, same fix
  category: bundled a real lockfile snapshot as
  `smp-pqc-inventory/tests/fixtures/sample-workspace-cargo-lock.txt` inside
  the crate instead. Verified by running `cargo test` against the actual
  extracted `cargo package` output, not just re-reading the source.
- Added `version` to `smp-pqc-cli`'s path dependencies on
  `smp-pqc-core`/`smp-pqc-network`/`smp-pqc-inventory`: crates.io resolves
  a published crate's dependencies from the registry, not local paths, and
  refuses to publish path-only dependencies without one.

## [0.1.0] - 2026-07-30

Initial release. Every item below is real, working, and tested (`cargo test
--workspace` currently runs 70 tests across the Rust workspace, plus a
separately-verified Lean 4 proof suite) — see `README.md`'s Status section
for what's still explicitly *not* implemented, and why.

### Added

- **`smp-pqc-core`**: safe wrappers over the RustCrypto `ml-kem` (FIPS 203),
  `ml-dsa` (FIPS 204), and `slh-dsa` (FIPS 205) crates, plus an illustrative
  X25519 + ML-KEM-768 hybrid KEM. Proptest-based property tests, adversarial
  tests (wrong keys, corrupted ciphertext/signature bytes, ML-KEM implicit
  rejection), and a `basic_usage` library example.
- **`smp-pqc-core/tests/acvp.rs`**: NIST ACVP known-answer tests against
  sampled real reference vectors (`test-vectors/acvp/`) covering ML-KEM
  keygen/encapsulation/decapsulation and ML-DSA/SLH-DSA keygen/signature
  verification — validated against NIST's own ground truth, not just
  internal self-consistency.
- **`smp-pqc-core/fuzz`**: a `cargo-fuzz` target for the algorithm-name
  parsers (Linux-only; runs in CI, not on Windows).
- **`smp-pqc-cli`** (`smp-pqc` binary): `test kem`/`test sig` (correctness
  roundtrips), `scan tls` (TLS PQC/hybrid handshake scanning), `inventory`
  (cryptography inventory / CBOM generation). `bench`, `verify --formal`,
  and `tee-run --attest` exist as subcommands but exit with a specific,
  honest error rather than faking output — see below.
- **`smp-pqc-bench`**: Criterion benchmarks for keygen/encapsulate/decapsulate
  and keygen/sign/verify across every ML-KEM/ML-DSA/SLH-DSA parameter set,
  plus an X25519 classical baseline.
- **`smp-pqc-network`**: real TLS 1.3 handshake scanning via rustls 0.23's
  native ML-KEM/hybrid support (`aws-lc-rs` provider) — reports the actually
  negotiated key-exchange group, not just what was offered.
- **`smp-pqc-inventory`**: Cargo.lock scanning + crypto-crate classification
  + CycloneDX-shaped CBOM generation.
- **`smp-pqc-verify`**: a Lean 4 project with machine-checked, `sorry`-free
  proofs about `smp-pqc-core`'s control-flow logic (hybrid KEM combiner,
  signature-report aggregation) — not the cryptographic primitives
  themselves.
- CI (`.github/workflows/ci.yml`): build+test on Ubuntu and Windows,
  fmt+clippy+doc lint, a Linux-only fuzz smoke test, and a Lean
  verification job.

### Known limitations (by design, not oversight)

- SSH/QUIC scanning: not implemented. Blocked on integration work (async
  runtime, algorithm introspection), not on algorithm support — `russh`
  already implements the right hybrid KEX. See `docs/threat-model.md`.
- AF_XDP zero-copy benchmarking and TEE attestation: not implemented.
  Blocked on hardware even under WSL2 (investigated and confirmed during
  development — WSL2's virtual NIC and lack of enclave passthrough rule
  both out). See `docs/threat-model.md`.
- Side-channel/constant-time verification: not implemented. Needs dedicated
  timing-analysis tooling (e.g. dudect-style), not a unit test.
- `smp-pqc-verify` proves control-flow properties, not primitive security;
  it's hand-written Lean modeling the Rust logic, not extracted from it, so
  it can silently drift out of sync if the Rust changes without a matching
  Lean update — there's no automated check tying the two together yet.

