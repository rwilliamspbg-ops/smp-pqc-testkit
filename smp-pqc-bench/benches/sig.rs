//! Signature benchmarks: ML-DSA-44/65/87 and all 12 SLH-DSA parameter sets.
//!
//! SLH-DSA's "s" (small-signature) variants are dramatically slower to sign
//! than everything else here -- see smp-pqc-core's module docs for the
//! debug-build-specific version of this same story. In *release* mode
//! (which `cargo bench` always uses) SLH-DSA-SHAKE-256s still costs roughly
//! 1-2 orders of magnitude more per signing operation than ML-DSA-65. To
//! keep a full `cargo bench` run to a few minutes instead of tens of
//! minutes, the "s" variants use a reduced Criterion sample size (10, the
//! library minimum) instead of the default ~100; their reported confidence
//! intervals are correspondingly wider. Run with:
//! `cargo bench -p smp-pqc-bench --bench sig`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ml_dsa::{Generate, Keypair, MlDsa44, MlDsa65, MlDsa87, Signer, Verifier};
use rand::thread_rng;
use slh_dsa::signature::{Keypair as SlhKeypair, RandomizedSigner, Verifier as SlhVerifier};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};

const MESSAGE: &[u8] = b"smp-pqc-bench benchmark message";

macro_rules! bench_ml_dsa {
    ($group:expr, $name:literal, $ty:ty) => {{
        $group.bench_function(BenchmarkId::new("keygen", $name), |b| {
            b.iter(ml_dsa::SigningKey::<$ty>::generate);
        });

        let sk = ml_dsa::SigningKey::<$ty>::generate();
        $group.bench_function(BenchmarkId::new("sign", $name), |b| {
            b.iter(|| sk.sign(MESSAGE));
        });

        let vk = sk.verifying_key();
        let sig = sk.sign(MESSAGE);
        $group.bench_function(BenchmarkId::new("verify", $name), |b| {
            b.iter(|| vk.verify(MESSAGE, &sig));
        });
    }};
}

macro_rules! bench_slh_dsa {
    ($group:expr, $name:literal, $ty:ty, $sample_size:expr) => {{
        $group.sample_size($sample_size);

        $group.bench_function(BenchmarkId::new("keygen", $name), |b| {
            b.iter(|| slh_dsa::SigningKey::<$ty>::new(&mut thread_rng()));
        });

        let sk = slh_dsa::SigningKey::<$ty>::new(&mut thread_rng());
        $group.bench_function(BenchmarkId::new("sign", $name), |b| {
            b.iter(|| sk.sign_with_rng(&mut thread_rng(), MESSAGE));
        });

        let vk = sk.verifying_key();
        let sig = sk.sign_with_rng(&mut thread_rng(), MESSAGE);
        $group.bench_function(BenchmarkId::new("verify", $name), |b| {
            b.iter(|| vk.verify(MESSAGE, &sig));
        });
    }};
}

fn ml_dsa_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa");
    bench_ml_dsa!(group, "ML-DSA-44", MlDsa44);
    bench_ml_dsa!(group, "ML-DSA-65", MlDsa65);
    bench_ml_dsa!(group, "ML-DSA-87", MlDsa87);
    group.finish();
}

fn slh_dsa_fast_variant_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_fast");
    bench_slh_dsa!(group, "SLH-DSA-SHAKE-128f", Shake128f, 20);
    bench_slh_dsa!(group, "SLH-DSA-SHAKE-192f", Shake192f, 20);
    bench_slh_dsa!(group, "SLH-DSA-SHAKE-256f", Shake256f, 10);
    bench_slh_dsa!(group, "SLH-DSA-SHA2-128f", Sha2_128f, 20);
    bench_slh_dsa!(group, "SLH-DSA-SHA2-192f", Sha2_192f, 20);
    bench_slh_dsa!(group, "SLH-DSA-SHA2-256f", Sha2_256f, 10);
    group.finish();
}

/// The "s" (small-signature) variants: much slower to sign than "f", hence
/// the library-minimum sample size of 10 -- see module docs.
fn slh_dsa_small_variant_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_small");
    bench_slh_dsa!(group, "SLH-DSA-SHAKE-128s", Shake128s, 10);
    bench_slh_dsa!(group, "SLH-DSA-SHAKE-192s", Shake192s, 10);
    bench_slh_dsa!(group, "SLH-DSA-SHAKE-256s", Shake256s, 10);
    bench_slh_dsa!(group, "SLH-DSA-SHA2-128s", Sha2_128s, 10);
    bench_slh_dsa!(group, "SLH-DSA-SHA2-192s", Sha2_192s, 10);
    bench_slh_dsa!(group, "SLH-DSA-SHA2-256s", Sha2_256s, 10);
    group.finish();
}

criterion_group!(
    benches,
    ml_dsa_benches,
    slh_dsa_fast_variant_benches,
    slh_dsa_small_variant_benches
);
criterion_main!(benches);
