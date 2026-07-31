//! Constant-time check for ML-KEM-512 decapsulation, using the [DudeCT]
//! statistical methodology (Reparaz, Balasch, Verbauwhede) via the
//! [`dudect-bencher`] crate.
//!
//! [DudeCT]: https://eprint.iacr.org/2016/1123.pdf
//! [`dudect-bencher`]: https://crates.io/crates/dudect-bencher
//!
//! # What this tests, and why
//!
//! ML-KEM's decapsulation uses *implicit rejection* (FIPS 203 Algorithm 18,
//! also discussed in `smp-pqc-core/src/kem.rs`'s module docs): a corrupted
//! ciphertext must not cause a decapsulation error, or take a
//! detectably-different amount of time, compared to a valid one — either
//! would let an adversary use decapsulation as a distinguishing oracle,
//! which is exactly what implicit rejection exists to prevent (a CCA2
//! concern). This harness runs many decapsulations, split into two
//! classes — `Left` = valid ciphertext, `Right` = a single flipped bit
//! somewhere in the ciphertext — and checks whether their timing
//! distributions are statistically distinguishable.
//!
//! Only `decapsulate()` itself is inside the timed closure; ciphertexts are
//! generated and (for the Right class) corrupted *before* timing starts, so
//! `encapsulate()`'s own timing never contaminates the measurement.
//!
//! # What a result here does and does not mean
//!
//! - A low t-statistic is evidence of *no detected* timing leak under this
//!   specific input distribution, on this specific machine, right now. It
//!   is not a proof of constant-time-ness in general -- DudeCT's own README
//!   is explicit about this: "it is not possible to prove that a function
//!   always runs in constant time." A different corruption pattern, a
//!   different CPU, or a different compiler/optimization level could reveal
//!   a leak this run didn't.
//! - A high t-statistic is a genuine finding worth investigating, but
//!   first rule out measurement noise: this needs to run on a quiet
//!   machine (no other load, ideally CPU-pinned, frequency scaling
//!   disabled) to be trustworthy. A shared/virtualized/laptop-with-thermal-
//!   throttling environment can produce false positives. See
//!   `docs/threat-model.md`'s side-channel section for the fuller caveat.
//!
//! Run with:
//! ```bash
//! cargo run -p smp-pqc-core --release --example dudect_ml_kem_512_decap
//! ```
//! (`--release` matters enormously here -- timing an unoptimized build
//! measures the interpreter/debug-info overhead, not the algorithm.)

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::MlKem512;

const SAMPLES_PER_RUN: usize = 20_000;

fn ml_kem_512_decapsulate_valid_vs_corrupted_ciphertext(runner: &mut CtRunner, rng: &mut BenchRng) {
    // One fixed keypair for the whole run: we're testing whether
    // decapsulate()'s timing depends on ciphertext validity, not on which
    // key is in use.
    let (dk, ek) = MlKem512::generate_keypair();

    let mut inputs = Vec::with_capacity(SAMPLES_PER_RUN);
    let mut classes = Vec::with_capacity(SAMPLES_PER_RUN);

    for _ in 0..SAMPLES_PER_RUN {
        let (mut ct, _shared_secret) = ek.encapsulate();
        if rng.random::<bool>() {
            classes.push(Class::Left); // valid ciphertext
        } else {
            let idx = rng.random_range(0..ct.len());
            let flip = rng.random_range(1u8..=255);
            ct[idx] ^= flip;
            classes.push(Class::Right); // corrupted ciphertext
        }
        inputs.push(ct);
    }

    for (class, ct) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || dk.decapsulate(&ct));
    }
}

ctbench_main!(ml_kem_512_decapsulate_valid_vs_corrupted_ciphertext);
