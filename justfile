# Common dev commands for smp-pqc-testkit. Run `just` to list them, or see
# CONTRIBUTING.md / RELEASING.md for the full narrative versions.

default:
    @just --list

# Build everything, including tests/examples/benches.
build:
    cargo build --workspace --all-targets --locked

# Run the full workspace test suite (~100-110s: SLH-DSA-256s is slow in
# unoptimized builds even with the dependency opt-level override).
test:
    cargo test --workspace --locked

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Supply-chain gate: RustSec advisories, license compliance, banned crates,
# unexpected registries/git sources. See deny.toml for documented exceptions.
deny:
    cargo deny check

# Per-crate coverage matching what ci.yml's `coverage` job enforces:
# smp-pqc-core at a 90% floor, smp-pqc-cli at a 90%/80% floor (see the
# comment in ci.yml for why these differ).
coverage:
    cargo llvm-cov -p smp-pqc-core --lib --tests --locked --summary-only
    cargo llvm-cov -p smp-pqc-cli --bins --tests --locked --summary-only

# Build+test against this workspace's pinned MSRV (see rust-version in
# Cargo.toml). Requires `rustup toolchain install 1.88.0` first.
msrv:
    cargo +1.88.0 build --workspace --all-targets --locked
    cargo +1.88.0 test --workspace --locked

# cargo-fuzz needs a nightly toolchain + libFuzzer/ASan -- Linux-only in
# practice, not runnable on this project's Windows dev machine (see
# docs/threat-model.md). CI runs this on ubuntu-latest.
fuzz:
    cd smp-pqc-core && cargo +nightly fuzz run parse_algorithm_names -- -max_total_time=30

# Lean 4 formal verification proofs. Requires a Lean toolchain via elan --
# see smp-pqc-verify/README.md.
lean:
    cd smp-pqc-verify && lake build

# DudeCT-based constant-time checks. --release matters -- see each example
# file's doc comment. Not wired into CI (shared runners are too noisy for
# trustworthy timing measurements) -- run manually on a quiet machine.
dudect example="dudect_ml_kem_decap":
    cargo run -p smp-pqc-core --release --example {{example}}

# Dry-run crates.io packaging for the three independent crates (matches
# ci.yml's package-check job) -- catches metadata/packaging regressions
# before an actual publish attempt. smp-pqc-cli is excluded: its path+version
# dependencies only resolve once the others are actually published, so this
# check can't run for it pre-publish (see .github/workflows/ci.yml).
package-check:
    cargo package -p smp-pqc-core --locked
    cargo package -p smp-pqc-network --locked
    cargo package -p smp-pqc-inventory --locked

# The full local verification pass from RELEASING.md -- run this before
# tagging a release so a red CI run doesn't happen on a pushed tag.
release-check: build test fmt-check clippy doc deny lean
    @echo "All release-verification checks passed."
