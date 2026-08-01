# Roadmap

This is the working roadmap for smp-pqc-testkit past 1.0.0. It exists to
answer one question honestly: what's actually planned, what's blocked and
why, and what's been deliberately cut. See
[docs/threat-model.md](threat-model.md) for the threat model and the
platform-level blockers (AF_XDP, TEE attestation) that predate this
document and still apply.

## The strategic choice this roadmap makes

There are two different products this project could become:

1. **Narrow and deep**: a pure-Rust, memory-safe PQC test kit validated
   against real NIST ACVP vectors, with Lean-proved control-flow logic,
   that never fakes a check it hasn't actually run. This is what
   smp-pqc-testkit is today.
2. **Broad and shallow**: a multi-backend comparison tool covering every
   NIST candidate (Falcon, Classic McEliece, BIKE, HQC) across multiple
   implementations (RustCrypto, liboqs via FFI, aws-lc-rs), competing with
   liboqs on algorithm count.

This roadmap deliberately chooses (1). liboqs already covers far more
algorithms than this project ever will -- in C, with a correspondingly
larger attack surface. Bolting a liboqs FFI backend onto this kit wouldn't
make it competitive with liboqs on breadth; it would just import liboqs's
risk profile into a project whose entire pitch is avoiding that. Backend
plurality (a second, *verified* Rust backend like libcrux) is still on
the table -- see Phase 3 -- but algorithm breadth via FFI is not.

## Phase 0 -- Close the documentation gaps (small, days)

- [x] CI coverage/MSRV/supply-chain gates, contributor scaffolding,
      justfile, badges -- done as part of the 1.0.0 release.
- [x] Architecture diagram (README's Architecture section)
- [x] Comparison table vs. liboqs / PQClean (`docs/comparison.md`)
- [x] Committed, reproducible benchmark run with hardware/OS/rustc specs
      (`docs/benchmarks.md`)
- [x] This document, linked from README's Roadmap section
- [x] Fixed the SECURITY.md/CODE_OF_CONDUCT.md GitHub Discussions
      inconsistency found while writing this roadmap: both pointed to
      Discussions as a fallback contact channel, but Discussions is
      disabled on this repo. Docs were updated to point to direct
      maintainer contact instead rather than assume the toggle would be
      flipped; enabling Discussions is still on the table if there's ever
      enough traffic to justify it.

## Phase 1 -- Deepen what's already differentiated (medium-large, weeks)

- [x] Extend DudeCT constant-time coverage to every ML-KEM parameter set
      and ML-DSA/SLH-DSA signing -- turned out this was **already done**
      in the 0.2.0 release (all three ML-KEM sizes, one ML-DSA and one
      SLH-DSA parameter set, plus the hybrid combiner), but
      `docs/threat-model.md`'s side-channel section had never been
      updated to say so -- it still described only the original
      single-check state. Fixed the doc, re-ran all six checks for real,
      current numbers (see `docs/benchmarks.md`). Still not exhaustive
      (ML-DSA-44/87 and 11 of 12 SLH-DSA parameter sets remain
      uncovered), but that's now accurately what the docs say too.
- [ ] A real byte-serialization API for keys/ciphertexts/signatures in
      `smp-pqc-core` -- this is the actual prerequisite for broader
      fuzzing (the current fuzz target only covers algorithm-name string
      parsing because no serialization API exists yet to fuzz)
- [x] Investigated `scan quic`'s remaining gap directly against the
      vendored `quinn-proto` 0.11.16 source rather than trusting the
      existing code comment at face value. Confirmed precisely: rustls
      itself exposes `negotiated_key_exchange_group()` as a stable public
      API -- `scan tls` already uses exactly this
      (`smp-pqc-network/src/scan.rs:157`), no special feature needed.
      QUIC's gap is entirely on quinn's side: `quinn_proto::crypto::rustls
      ::HandshakeData` (the struct quinn hands back from
      `Connection::handshake_data()`, the only sanctioned way to reach
      backend-specific data from quinn's public API) only includes the
      `negotiated_key_exchange_group` field when quinn-proto's own
      `__rustls-post-quantum-test` Cargo feature is enabled -- a
      double-underscore-prefixed feature, which is the Rust ecosystem's
      convention for "internal, not covered by our semver guarantees, use
      at your own risk." Cargo doesn't technically stop a downstream
      crate from enabling it, but doing so means depending on an API
      quinn's own maintainers have explicitly marked as unstable and
      could rename/remove without a semver-major release. There's no
      alternative path to the underlying rustls session object from
      quinn's public `Connection` type. **Decision needed, not a trivial
      fix**: enable the private feature and accept the maintenance risk,
      or wait for quinn to stabilize it. Not flipped on in this pass --
      that's a deliberate tradeoff for whoever owns this next to make
      explicitly, not something to slip in quietly.
- [x] `no_std` feasibility investigation for `smp-pqc-core` -- **better
      news than expected.** Checked the actual vendored crate sources
      (not assumed): `ml-kem` and `ml-dsa` are unconditionally
      `#![no_std]`; `x25519-dalek` 3.0.0 is unconditionally `#![no_std]`;
      `anyhow` and `thiserror` 2.x both support no_std via
      `default-features = false` (dropping their `std` feature);
      `serde`/`serde_json` support no_std via an `alloc` feature. The one
      genuine unknown is `slh-dsa` 0.1.0, which ties `#![no_std]` to its
      *non-default* `alloc` feature being *disabled*
      (`#![cfg_attr(not(feature = "alloc"), no_std)]`) -- using it as
      `no_std + alloc` together (which is what a real embedded target
      would want, since SLH-DSA's key/signature sizes need heap
      allocation) isn't obviously exercised by its own feature flags and
      needs an actual compile test, not a read of the manifest. In
      `smp-pqc-core`'s own code, the only std-specific usage found was
      `std::str::FromStr` in `kem.rs`/`sig.rs` -- trivially
      `core::str::FromStr` instead, since `FromStr` lives in `core`.
      `rand`/`rand_core` 0.8's no_std story needs an entropy-source
      decision for whatever target this actually runs on (no_std has no
      OS RNG by default). Net assessment: **this is realistically a
      small-to-medium task, not the speculative "probably blocked"
      guess** in the original strategic review -- next step is an actual
      `--no-default-features --target thumbv7em-none-eabihf`-style build
      attempt to confirm slh-dsa's behavior, not more manifest-reading.

## Phase 2 -- Benchmarking rigor (medium, ongoing)

- [ ] Publish Criterion's existing HTML reports
      (`target/criterion/report/index.html`) via a GitHub Pages CI job --
      the cheapest "rich dashboard" win available, since Criterion already
      generates this and nothing currently surfaces it
- [ ] Document a reproducible benchmarking methodology (CPU pinning,
      frequency scaling disabled) as a `just` recipe + doc
- [ ] ARM64 cross-compilation + CI job (GitHub-hosted ARM64 runners)
- Cut from the original draft: WASM benchmarking. Most of this stack
  (`quinn`, `russh`, `aws-lc-rs`) doesn't target wasm; only
  `smp-pqc-core`'s bare primitives could run there, which is a narrow win
  not worth prioritizing yet.

## Phase 3 -- One differentiated bet, plus small scoped wins (large, months)

- [ ] **libcrux as a second backend.** `docs/threat-model.md` already
      cites libcrux as the project's reference for "real," HACL*-derived
      verified-primitive proofs. Actually integrating it (not just citing
      it) -- verified primitives plus this kit's protocol/control-flow
      testing -- is a genuinely rare combination and a much stronger
      "top-tier" story than liboqs-style breadth. **Investigated for
      real** (added `libcrux = { features = ["mlkem", "mldsa"] }` to a
      scratch project and built it, rather than reading docs.rs and
      guessing):
      - It's real and it builds. ML-KEM/ML-DSA live in separate
        `libcrux-ml-kem`/`libcrux-ml-dsa` crates (both `0.0.10` as of this
        writing), re-exported through the top-level `libcrux` crate
        (`0.0.5`) under `libcrux::algorithms::{mlkem, mldsa}`.
      - **Both are pre-1.0 (`0.0.x`)** -- expect breaking changes between
        minor versions, not a stable dependency to pin against casually.
      - **The API shape is fundamentally different from RustCrypto's**,
        not a drop-in swap: RustCrypto's `ml-kem`/`ml-dsa` use generic
        types per parameter set (`MlKem768::generate_keypair()`
        implementing `Encapsulate`/`Decapsulate` traits); libcrux uses
        free functions in a separate module per parameter set
        (`libcrux_ml_kem::mlkem768::generate_key_pair(...)`,
        `::encapsulate(...)`, `::decapsulate(...)`), with its own key/
        ciphertext types and, in places, both a "kyber"-named and
        "mlkem"-named function pair (transitional naming from the
        pre-standardization Kyber submission, presumably).
      - **Conclusion: this confirms the large/months estimate, it isn't
        downsized by the investigation.** A real second backend needs a
        trait abstraction designed in `smp-pqc-core` first (something
        both RustCrypto's and libcrux's shapes can implement), then two
        implementations behind it, then tests proving both produce
        interoperable results (a ciphertext one backend produces should
        decapsulate correctly on the other, if that's even meaningful
        given libcrux's internal Kyber/ML-KEM naming ambiguity above --
        needs its own investigation). Also worth weighing before
        starting: pinning a production dependency to a `0.0.x` crate is
        itself a decision with real tradeoffs, independent of the
        integration effort.
- [x] PQC "readiness score": implemented in `smp-pqc-inventory` (see
      `readiness.rs`) and wired into `smp-pqc-cli`'s `inventory` text
      output. Deliberately narrower than "weight PQC/classical/
      quantum-vulnerable counts into one number" -- only counts
      KeyExchange/Signature-category crates (where PQC-vs-classical is
      the crate's whole purpose), and reports PQC-capable secure-protocol
      crates (rustls/russh) separately rather than folding them in, since
      those support both classical and hybrid handshakes and a static
      lockfile scan can't say which one a given connection actually used
      -- see the module's own honesty note.
- [ ] X.509 PQC/hybrid certificate testing, tied into the existing TLS
      scanner
- Cut from the original draft:
  - Multi-ecosystem CBOM (Go modules, npm, etc.) -- this turns a focused
    Rust crypto-inventory tool into a general SBOM scanner, competing
    with mature dedicated tools (Syft, cdxgen, Trivy) that already do this
    well. Better to make the CBOM output interoperate with those tools
    than reimplement their parsers.
  - IKEv2, WireGuard hybrid KEX, Wireshark dissectors -- each is its own
    multi-month project in a different tech stack. WireGuard doesn't even
    have a standardized PQC hybrid yet (Rosenpass is still experimental).
  - Falcon, Classic McEliece, BIKE/HQC, pluggable liboqs backend -- see
    "The strategic choice" above.

## Phase 4 -- Visibility (parallel, cheap, do early)

- [ ] Submit to awesome-post-quantum-style lists, write a "why this
      exists" post -- highest leverage-per-hour item on this whole
      roadmap. Requires opening PRs against third-party repos or
      publishing externally -- needs explicit sign-off each time, not
      something to automate.
- [ ] Tighten README's opening pitch to lead with the actual
      differentiators (pure-Rust safety, real ACVP validation, Lean
      proofs) rather than a generic description
- Cut from the original draft:
  - Renaming the project -- disruptive to a published crate name for
    cosmetic benefit; fix the messaging instead.
  - Discord/Matrix -- GitHub Discussions alone is enough until there's
    actual community traffic to justify moderating real-time chat.
  - Paid third-party audits -- not actionable without funding; revisit
    later.

## What "done" looks like for this document

This file gets updated in place as phases complete or get re-scoped --
it's a living plan, not a snapshot. If an item here turns out to be
infeasible (like AF_XDP/TEE in the original threat model), that gets
written down here with the reason, the same way this project handles
every other honest limitation.
