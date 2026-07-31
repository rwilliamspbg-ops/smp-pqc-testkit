# smp-pqc-verify

A small Lean 4 project with machine-checked proofs about **control-flow
safety properties** of `smp-pqc-core`'s Rust logic -- not proofs about the
cryptographic primitives (ML-KEM/ML-DSA/SLH-DSA) themselves. See
`docs/threat-model.md` at the repo root for why re-proving primitives from
scratch is out of scope, and why this project cites
[libcrux](https://github.com/cryspen/libcrux)'s existing HACL*-derived
proofs for that instead.

## What's actually proved here

- **`SmpPqcVerify/HybridHandshake.lean`**: models the combiner decision in
  `smp-pqc-core::kem::run_hybrid` (`if classical_ok && pq_ok { ... }`) and
  proves a combined secret is formed *if and only if* both the classical
  (X25519) and post-quantum (ML-KEM-768) legs independently succeeded --
  ruling out, for example, an accidental `||` in place of `&&`, or any other
  hidden path to producing a secret from only one leg.
- **`SmpPqcVerify/SignatureVerification.lean`**: models the per-iteration
  accounting in `smp-pqc-core::sig::run` and proves that if the aggregate
  report says `all_passed`, every single iteration genuinely verified *and*
  correctly rejected its tampered counterpart -- the counters can't get to
  zero by some other bookkeeping accident, because they're proved monotone
  (only ever incremented) by induction over the whole iteration list.
- **`SmpPqcVerify/ExtendedHybrid.lean`**: generalises the combiner model to
  all three ML-KEM parameter sets (512, 768, 1024) and proves the
  algorithm-agnostic property: the combiner logic depends only on the boolean
  `classical_ok && pq_ok`, not on which KEM algorithm is used. Proves the
  same "iff both legs succeed" invariant and the one-sided failure lemmas for
  all parameter sets.

Every theorem here is checked against Lean's kernel with **no `sorry`** and
no dependency on unproven axioms beyond Lean's own trusted core (`propext`,
`Quot.sound` -- verify yourself with `#print axioms <theorem name>`, or see
the check baked into `lake build` succeeding at all: a `sorry` would still
build, but only `#print axioms` reveals it depends on `sorryAx`).

## What isn't proved here (read before relying on this for anything)

- Nothing about whether X25519 or ML-KEM-768 are themselves secure, or
  whether the RustCrypto crates correctly implement them -- that's what
  `smp-pqc-core/tests/acvp.rs`'s NIST ACVP known-answer tests are for, and
  what libcrux's formal proofs cover for its own implementation.
  - Nothing about timing side-channels -- see `docs/threat-model.md`'s
    side-channel section.
- No connection to the compiled Rust binary: these Lean models are hand-
  written analogues of the Rust control flow, checked for faithfulness by
  code review and by matching the exact conditions/expressions in the Rust
  source (each file's doc comment names the exact function/line it models),
  not by any automated Rust-to-Lean extraction. If `kem.rs`/`sig.rs` change,
  these models need updating by hand, and could drift silently if not kept
  in sync -- there is no CI check enforcing that the Lean model still
  matches the Rust source line-for-line.

## Building

```bash
lake build
```

Requires a Lean 4 toolchain (this project pins `leanprover/lean4:v4.32.2`
in `lean-toolchain`; run via [elan](https://github.com/leanprover/elan),
which auto-installs the pinned version on first `lake`/`lean` invocation).
Runs in CI on `ubuntu-latest` (the `lean-verify` job in
`.github/workflows/ci.yml`) -- not part of the main Rust build-test matrix,
since it's a separate toolchain.
