//! Constant-time check for SLH-DSA (FIPS 205) signing, using the [DudeCT]
//! statistical methodology (Reparaz, Balasch, Verbauwhede) via the
//! [`dudect-bencher`] crate.
//!
//! [DudeCT]: https://eprint.iacr.org/2016/1123.pdf
//! [`dudect-bencher`]: https://crates.io/crates/dudect-bencher
//!
//! # What this tests, and why
//!
//! SLH-DSA (based on SPHINCS+) is a stateless hash-based signature
//! scheme. Its signing process involves computing a hash tree (FORS
//! few-time signatures + Merkle tree authentication path). While the
//! tree structure is deterministic for a given message, the randomizer
//! (a 32-byte value from the RNG) affects the hash tree computation.
//!
//! Like ML-DSA, SLH-DSA signing uses randomness. The key question is
//! whether timing depends on the *secret key* rather than just the
//! public message and RNG output. This harness uses a FIXED secret key
//! and FIXED message, varying only the RNG randomizer to test for
//! secret-dependent timing.
//!
//! Classes:
//! - `Left`: signing with one RNG randomizer value
//! - `Right`: signing with a different RNG randomizer value
//!
//! Both use the same secret key and message. If timing correlates with
//! class, it suggests the secret key interacts with the randomizer in a
//! timing-observable way.
//!
//! Only `sign_with_rng()` itself is inside the timed closure.
//!
//! # What a result here does and does not mean
//!
//! - A low t-statistic is evidence of *no detected* secret-dependent
//!   timing leak. SLH-DSA's hash-tree computation is expected to be
//!   data-dependent (different randomizer → different tree branches
//!   accessed), but that data is public randomness, not the secret key.
//!   What we're testing is whether secret key material leaks via memory
//!   access patterns depending on the randomizer.
//! - A high t-statistic is a genuine finding worth investigating.
//!
//! Run with:
//! ```bash
//! cargo run -p smp-pqc-core --release --example dudect_slh_dsa_sign
//! ```
//! (`--release` matters enormously here.)

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use slh_dsa::signature::RandomizedSigner;
use slh_dsa::{Sha2_128f, SigningKey};

const SAMPLES_PER_RUN: usize = 20_000;
const MESSAGE: &[u8] = b"smp-pqc-testkit constant-time SLH-DSA signing test";

fn slh_dsa_sha2_128f_sign_randomizer_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    // One fixed keypair for the whole run.
    let mut rng_keypair = rand::thread_rng();
    let sk = SigningKey::<Sha2_128f>::new(&mut rng_keypair);

    let mut inputs = Vec::with_capacity(SAMPLES_PER_RUN);
    let mut classes = Vec::with_capacity(SAMPLES_PER_RUN);

    for _ in 0..SAMPLES_PER_RUN {
        // Use dudect's RNG to assign class — this determines which
        // randomizer we'll use for signing.
        let is_left = rng.random::<bool>();

        if is_left {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }

        // Input is a randomizer seed for this sample
        let randomizer: [u8; 32] = rng.random();
        inputs.push(randomizer);
    }

    for (class, randomizer) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            // Create a dedicated RNG seeded with this randomizer.
            // StdRng (from rand crate) implements CryptoRngCore and uses
            // ChaCha20 internally, suitable for SLH-DSA's sign_with_rng.
            use rand::rngs::StdRng;
            use rand::SeedableRng;
            let mut signer_rng = StdRng::from_seed(randomizer);
            let _sig = sk.sign_with_rng(&mut signer_rng, MESSAGE);
        });
    }
}

ctbench_main!(slh_dsa_sha2_128f_sign_randomizer_timing);
