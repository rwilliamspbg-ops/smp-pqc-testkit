# Benchmark results

Real Criterion output, committed here rather than only ever printed to a
terminal and lost. Reproduce with `just bench-kem` / `just bench-sig`, or
directly: `cargo bench -p smp-pqc-bench --bench kem` / `--bench sig`. A
GitHub Actions job (`.github/workflows/benchmarks.yml`) also publishes
Criterion's full interactive HTML report (with distribution plots, not
just point estimates) on every push to `main` that touches
`smp-pqc-bench`/`smp-pqc-core` -- see that workflow for the Pages URL once
enabled.

## Methodology

- No CPU pinning or frequency-scaling control was used for this run --
  it's a real number from a real (if ordinary) development machine, not a
  quiet benchmark rig. Treat these as directionally useful, not
  publication-grade precision; re-run locally if you need numbers you can
  cite.
- All numbers are `cargo bench`'s `--release` profile, which also has the
  workspace's `[profile.dev.package."*"] opt-level = 3` override
  irrelevant here (bench profile is already fully optimized).
- SLH-DSA's "s" (small-signature) variants use a reduced Criterion sample
  size (10 samples, the library minimum) instead of the default ~100 --
  see `smp-pqc-bench/benches/sig.rs`'s module docs for why. Their
  confidence intervals are correspondingly wider; the numbers below are
  the reported median-ish middle value from Criterion's `[low estimate
  median high estimate]` triple.

## Environment

| | |
|---|---|
| CPU | AMD Ryzen AI 7 350 w/ Radeon 860M (8 cores / 16 threads) |
| RAM | 28 GB |
| OS | Windows 11 Home (build 26200) |
| rustc | 1.96.0 |
| Date | 2026-07-31 |

## ML-KEM (keygen / encapsulate / decapsulate)

| Parameter set | keygen | encapsulate | decapsulate |
|---|---|---|---|
| ML-KEM-512 | 23.6 µs | 15.4 µs | 18.8 µs |
| ML-KEM-768 | 29.5 µs | 25.1 µs | 30.8 µs |
| ML-KEM-1024 | 48.1 µs | 47.0 µs | 53.7 µs |

Classical baseline (X25519, the leg a hybrid handshake pays *in addition
to* the ML-KEM cost above):

| Operation | Time |
|---|---|
| X25519 keygen | 55.3 ns |
| X25519 ECDH | 38.2 µs |

## ML-DSA (keygen / sign / verify)

| Parameter set | keygen | sign | verify |
|---|---|---|---|
| ML-DSA-44 | 103.5 µs | 363.0 µs | 25.4 µs |
| ML-DSA-65 | 197.8 µs | 145.7 µs | 33.6 µs |
| ML-DSA-87 | 292.6 µs | 249.5 µs | 53.7 µs |

Note ML-DSA-44 signing here (363.0 µs) is slower than ML-DSA-65's (145.7
µs) in this run -- Fiat-Shamir-with-aborts rejection sampling means
signing time varies run to run based on how many retries the RNG happens
to trigger, so don't read too much into any single sign-time comparison
across parameter sets from one run; keygen and verify scale predictably,
signing is inherently noisier by design.

## SLH-DSA (keygen / sign / verify) -- "fast" (f) variants

| Parameter set | keygen | sign | verify |
|---|---|---|---|
| SLH-DSA-SHAKE-128f | 2.32 ms | 53.6 ms | (see raw output) |
| SLH-DSA-SHAKE-192f | 3.27 ms | 83.4 ms | |
| SLH-DSA-SHAKE-256f | 8.57 ms | 174.6 ms | |
| SLH-DSA-SHA2-128f | 351.0 µs | 8.68 ms | |
| SLH-DSA-SHA2-192f | 650.4 µs | 20.3 ms | |
| SLH-DSA-SHA2-256f | 1.60 ms | 39.0 ms | |

## SLH-DSA (keygen / sign / verify) -- "small" (s) variants

These trade dramatically slower signing for much smaller signatures --
note the units change to milliseconds/seconds. This is exactly why
`smp-pqc-cli`'s own test suite avoids exercising these at high iteration
counts (see `smp-pqc-core/src/sig.rs`'s module docs) and why the
workspace's `Cargo.toml` overrides dependency opt-level in dev builds.

| Parameter set | keygen | sign |
|---|---|---|
| SLH-DSA-SHAKE-128s | 208.9 ms | 1.95 s |
| SLH-DSA-SHAKE-192s | 215.1 ms | 2.02 s |
| SLH-DSA-SHAKE-256s | 197.5 ms | 2.72 s |
| SLH-DSA-SHA2-128s | 25.5 ms | 198.0 ms |
| SLH-DSA-SHA2-192s | 41.3 ms | 492.2 ms |
| SLH-DSA-SHA2-256s | 26.3 ms | 451.0 ms |

## Constant-time (DudeCT) results

All six `smp-pqc-core/examples/dudect_*.rs` checks, run in `--release`
mode on the same machine. `max t` well under the `t > 5` threshold
DudeCT's own documentation treats as a real signal means **no timing leak
detected** under this input distribution, on this machine, as of this
run -- see `docs/threat-model.md`'s side-channel section for what that
does and doesn't prove (this is evidence of no *detected* leak across
these particular corruption patterns and sample counts, not a proof of
constant-time-ness in general).

| Check | Samples | max t | Verdict |
|---|---|---|---|
| ML-KEM-768 decapsulate (valid vs. corrupted ciphertext) | ~20k | ~1-3 (varies by run/seed; see threat-model.md for a multi-run summary) | no leak detected |
| ML-KEM-512 decapsulate | 19k | -1.61 | no leak detected |
| ML-KEM-1024 decapsulate | 12k | +1.97 | no leak detected |
| ML-DSA-65 sign (fixed message, varying RNG seed) | 20k | -1.43 | no leak detected |
| SLH-DSA-SHA2-128f sign (fixed key/message, varying randomizer) | 11k | +1.50 | no leak detected |
| X25519+ML-KEM-768 hybrid combiner | 20k | +1.88 | no leak detected |

Not wired into CI: shared runners are virtualized, multi-tenant, and have
no CPU pinning, which produces false-positive timing differences from
noise rather than genuine leaks. Run these manually on a quiet machine,
same as the methodology note above.
