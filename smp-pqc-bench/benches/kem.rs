//! KEM benchmarks: ML-KEM-512/768/1024 keygen/encapsulate/decapsulate, and
//! X25519 ECDH as the classical baseline for `--compare-classical`.
//!
//! Run with `cargo bench -p smp-pqc-bench --bench kem`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{MlKem1024, MlKem512, MlKem768};

macro_rules! bench_ml_kem {
    ($group:expr, $name:literal, $ty:ty) => {{
        $group.bench_function(BenchmarkId::new("keygen", $name), |b| {
            b.iter(<$ty>::generate_keypair);
        });

        let (dk, ek) = <$ty>::generate_keypair();
        $group.bench_function(BenchmarkId::new("encapsulate", $name), |b| {
            b.iter(|| ek.encapsulate());
        });

        let (ct, _k) = ek.encapsulate();
        $group.bench_function(BenchmarkId::new("decapsulate", $name), |b| {
            b.iter(|| dk.decapsulate(&ct));
        });
    }};
}

fn kem_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem");
    bench_ml_kem!(group, "ML-KEM-512", MlKem512);
    bench_ml_kem!(group, "ML-KEM-768", MlKem768);
    bench_ml_kem!(group, "ML-KEM-1024", MlKem1024);
    group.finish();
}

/// Classical baseline for comparison against the ML-KEM numbers above:
/// X25519 ephemeral ECDH is what a hybrid handshake pays *in addition to*
/// the ML-KEM cost, so the gap between this group and `ml_kem` is roughly
/// the PQC tax of moving from classical-only to hybrid.
fn classical_baseline_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("classical_baseline");

    group.bench_function("x25519_keygen", |b| {
        b.iter(x25519_dalek::EphemeralSecret::random);
    });

    group.bench_function("x25519_diffie_hellman", |b| {
        b.iter_batched(
            || {
                let alice = x25519_dalek::EphemeralSecret::random();
                let bob_public =
                    x25519_dalek::PublicKey::from(&x25519_dalek::EphemeralSecret::random());
                (alice, bob_public)
            },
            |(alice, bob_public)| alice.diffie_hellman(&bob_public),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, kem_benches, classical_baseline_benches);
criterion_main!(benches);
