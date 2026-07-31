//! Constant-time check for the X25519 + ML-KEM-768 hybrid KEM combiner,
//! using the [DudeCT] statistical methodology (Reparaz, Balasch, Verbauwhede)
//! via the [`dudect-bencher`] crate.
//!
//! [DudeCT]: https://eprint.iacr.org/2016/1123.pdf
//! [`dudect-bencher`]: https://crates.io/crates/dudect-bencher
//!
//! # What this tests, and why
//!
//! The hybrid KEM combiner in `smp-pqc-core::kem::run_hybrid` performs
//! both X25519 ECDH and ML-KEM-768 decapsulation, then combines the
//! shared secrets *only if both succeed*. The combination logic is:
//!
//! ```rust
//! if classical_ok && pq_ok {
//!     combined.extend_from_slice(&classical_shared_secret);
//!     combined.extend_from_slice(&pq_shared_secret);
//! }
//! ```
//!
//! This test checks whether the *combiner's control flow* leaks timing
//! information about which leg succeeded/failed. Specifically:
//! - `Left`: both X25519 and ML-KEM-768 succeed → combined secret produced
//! - `Right`: ML-KEM-768 decapsulation receives a corrupted ciphertext
//!   (implicit rejection → wrong shared secret) → NO combined secret
//!
//! The X25519 leg always succeeds (fresh keypair each iteration). The
//! only difference is whether the PQC leg's decapsulation produces the
//! expected key (valid ciphertext) or a pseudorandom implicit-rejection
//! key (corrupted ciphertext).
//!
//! If the `&&` short-circuits or the combiner branches on the result,
//! timing could differ. This is a control-flow side channel test, not
//! a primitive test — the underlying X25519 and ML-KEM are assumed
//! constant-time (separately tested).
//!
//! Only the hybrid roundtrip logic itself is inside the timed closure;
//! keypair generation and ciphertext preparation happen before timing.
//!
//! # What a result here does and does not mean
//!
//! - A low t-statistic is evidence that the combiner logic doesn't leak
//!   via timing differences between success/failure paths.
//! - A high t-statistic would suggest a branching leak in the combiner
//!   (e.g., accidental `||` instead of `&&`, or early return on failure).
//!
//! Run with:
//! ```bash
//! cargo run -p smp-pqc-core --release --example dudect_hybrid_kem
//! ```
//! (`--release` matters enormously here.)

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use ml_kem::kem::{Ciphertext, Decapsulate, Encapsulate, Kem};
use ml_kem::MlKem768;
use x25519_dalek::{EphemeralSecret, PublicKey};

const SAMPLES_PER_RUN: usize = 20_000;

#[derive(Clone)]
struct HybridInput {
    // Classical leg: pre-computed shared secret bytes for both sides
    classical_shared_alice: [u8; 32],
    classical_shared_bob: [u8; 32],
    // PQC leg: ciphertext and expected shared secret bytes
    ct: Ciphertext<MlKem768>,
    pq_shared_expected: Vec<u8>,
}

fn hybrid_kem_combiner_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Fixed ML-KEM-768 keypair for the whole run (PQC leg)
    let (dk_pqc, ek_pqc) = MlKem768::generate_keypair();

    let mut inputs = Vec::with_capacity(SAMPLES_PER_RUN);
    let mut classes = Vec::with_capacity(SAMPLES_PER_RUN);

    for _ in 0..SAMPLES_PER_RUN {
        // Classical leg: X25519 - always succeeds with fresh keypairs
        let alice_secret = EphemeralSecret::random();
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = EphemeralSecret::random();
        let bob_public = PublicKey::from(&bob_secret);
        let classical_shared_alice = alice_secret.diffie_hellman(&bob_public);
        let classical_shared_bob = bob_secret.diffie_hellman(&alice_public);

        // PQC leg: ML-KEM-768
        let (mut ct, pq_shared_expected) = ek_pqc.encapsulate();

        if rng.random::<bool>() {
            // Left class: valid ciphertext → both legs succeed
            classes.push(Class::Left);
        } else {
            // Right class: corrupted ciphertext → PQC leg implicitly rejects
            let idx = rng.random_range(0..ct.len());
            let flip = rng.random_range(1u8..=255);
            ct[idx] ^= flip;
            classes.push(Class::Right);
        }

        inputs.push(HybridInput {
            classical_shared_alice: classical_shared_alice.to_bytes(),
            classical_shared_bob: classical_shared_bob.to_bytes(),
            ct,
            pq_shared_expected: pq_shared_expected.as_slice().to_vec(),
        });
    }

    for (class, input) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            // Classical leg: compare pre-computed shared secret bytes
            let classical_ok = input.classical_shared_alice == input.classical_shared_bob;

            // PQC leg
            let pq_shared_received = dk_pqc.decapsulate(&input.ct);
            let pq_ok = input.pq_shared_expected == pq_shared_received.as_slice();

            // Combiner logic (from run_hybrid)
            if classical_ok && pq_ok {
                let mut _combined = Vec::with_capacity(64);
                _combined.extend_from_slice(&input.classical_shared_alice);
                _combined.extend_from_slice(&pq_shared_received);
            }
            // If either fails, no combined secret is produced
        });
    }
}

ctbench_main!(hybrid_kem_combiner_timing);
