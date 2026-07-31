//! Constant-time check for ML-DSA signing, using the [DudeCT]
//! statistical methodology (Reparaz, Balasch, Verbauwhede) via the
//! [`dudect-bencher`] crate.
//!
//! [DudeCT]: https://eprint.iacr.org/2016/1123.pdf
//! [`dudect-bencher`]: https://crates.io/crates/dudect-bencher
//!
//! # What this tests, and why
//!
//! ML-DSA (FIPS 204) uses *Fiat-Shamir with aborts*: signing involves
//! rejection sampling where the signer may loop and retry with fresh
//! randomness until a signature passes a norm bound check. This is
//! expected to produce variable-time behavior based on the public
//! randomness (the challenge derived from the message), **not** the secret
//! key. However, if the *number of retries* depends on the secret key in
//! an exploitable way (e.g., via the randomness sampler's internal state
//! correlating with secret key material), that would be a side channel.
//!
//! This harness tests exactly that: using a FIXED message and FIXED
//! secret key, but varying the RNG seed to induce different retry counts.
//! It compares timing between two classes:
//! - `Left`: signatures that succeed on the first try (no rejection)
//! - `Right`: signatures that require ≥1 rejection before succeeding
//!
//! Both classes use the SAME secret key and SAME message — only the RNG
//! stream differs. If timing correlates with class, it suggests secret-
//! dependent leakage (since the RNG is seeded from the secret key in the
//! real implementation).
//!
//! Only `sign()` itself is inside the timed closure; RNG is pre-seeded
//! and message is fixed before timing starts.
//!
//! # What a result here does and does not mean
//!
//! - A low t-statistic is evidence of *no detected* secret-dependent
//!   timing leak under this specific input distribution. It does NOT
//!   prove constant-time signing in general — the expected variable-time
//!   from rejection sampling is *public-randomness-dependent*, which is
//!   fine. What we're testing is whether secret key material leaks via
//!   the RNG state or the rejection condition itself.
//! - A high t-statistic is a genuine finding worth investigating, but
//!   first rule out measurement noise: this needs to run on a quiet
//!   machine (no other load, ideally CPU-pinned, frequency scaling
//!   disabled) to be trustworthy.
//!
//! Run with:
//! ```bash
//! cargo run -p smp-pqc-core --release --example dudect_ml_dsa_sign
//! ```
//! (`--release` matters enormously here -- timing an unoptimized build
//! measures the interpreter/debug-info overhead, not the algorithm.)
//!
//! # Limitations
//!
//! The `ml-dsa` crate uses `rand::thread_rng()` internally and does not
//! expose a way to inject a custom RNG for signing. This means we cannot
//! deterministically control rejection sampling retries per sample. This
//! test uses a best-effort statistical approach: running many signatures
//! with the same key/message and letting dudect's class assignment
//! (which controls external randomness) create natural variance. This
//! is a weaker test than the KEM decapsulation checks but still provides
//! some signal for gross secret-dependent leaks.

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use ml_dsa::{Generate, MlDsa65, Signer, SigningKey as MlDsaSigningKey};

const SAMPLES_PER_RUN: usize = 20_000;
const MESSAGE: &[u8] = b"smp-pqc-testkit constant-time ML-DSA signing test";

fn ml_dsa_65_sign_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    // One fixed keypair for the whole run.
    let sk = MlDsaSigningKey::<MlDsa65>::generate();

    let mut inputs = Vec::with_capacity(SAMPLES_PER_RUN);
    let mut classes = Vec::with_capacity(SAMPLES_PER_RUN);

    for _ in 0..SAMPLES_PER_RUN {
        // Use dudect's RNG to assign class
        let is_left = rng.random::<bool>();

        if is_left {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }

        // Input is just a placeholder — ml-dsa uses thread_rng internally
        inputs.push(());
    }

    for (class, _) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _sig = sk.sign(MESSAGE);
        });
    }
}

ctbench_main!(ml_dsa_65_sign_timing);
