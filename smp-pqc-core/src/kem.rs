//! Key Encapsulation Mechanism roundtrip testing: ML-KEM (FIPS 203) and an
//! X25519 + ML-KEM-768 classical/PQC hybrid.
//!
//! # Threat model note
//!
//! ML-KEM is defined with *implicit rejection* (FIPS 203 Algorithm 18): a
//! decapsulation call never returns an error, even for a corrupted or
//! adversarially-crafted ciphertext. Instead it deterministically derives a
//! pseudorandom "junk" key from the ciphertext and the decapsulation key's
//! secret seed, so a bad ciphertext silently produces a shared key that
//! doesn't match the encapsulator's — this is what stops a decapsulation
//! oracle from being usable as a distinguisher (a CCA2 concern). Callers
//! must never treat "decapsulate returned Ok" as "the ciphertext was
//! genuine" — the only valid check is comparing against the expected key
//! (e.g. via a subsequent authenticated message), which is exactly what
//! this module's `ml_kem_768_tampered_ciphertext_is_implicitly_rejected`
//! test (and the ACVP KAT's "modified ciphertext" cases in
//! `smp-pqc-core/tests/acvp.rs`) assert.

use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{MlKem1024, MlKem512, MlKem768};
use serde::{Deserialize, Serialize};

/// A NIST FIPS 203 ML-KEM parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    /// Security category 1 (~128-bit classical security).
    MlKem512,
    /// Security category 3 (~192-bit classical security); NIST's recommended default.
    MlKem768,
    /// Security category 5 (~256-bit classical security).
    MlKem1024,
}

impl KemAlgorithm {
    /// The canonical FIPS 203 name for this parameter set, e.g. `"ML-KEM-768"`.
    pub fn name(&self) -> &'static str {
        match self {
            KemAlgorithm::MlKem512 => "ML-KEM-512",
            KemAlgorithm::MlKem768 => "ML-KEM-768",
            KemAlgorithm::MlKem1024 => "ML-KEM-1024",
        }
    }
}

impl std::str::FromStr for KemAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "ml-kem-512" | "mlkem512" => Ok(KemAlgorithm::MlKem512),
            "ml-kem-768" | "mlkem768" => Ok(KemAlgorithm::MlKem768),
            "ml-kem-1024" | "mlkem1024" => Ok(KemAlgorithm::MlKem1024),
            other => Err(anyhow::anyhow!("unknown KEM algorithm: {other}")),
        }
    }
}

/// Result of running `iterations` independent keygen/encapsulate/decapsulate
/// cycles for a single algorithm.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct KemReport {
    pub algorithm: KemAlgorithm,
    pub iterations: usize,
    pub successes: usize,
    pub failures: usize,
}

impl KemReport {
    /// True only if every iteration succeeded and none were skipped/errored.
    pub fn all_passed(&self) -> bool {
        self.failures == 0 && self.successes == self.iterations
    }
}

/// One ML-KEM keygen -> encapsulate -> decapsulate cycle. Returns true if the
/// encapsulator's and decapsulator's shared keys match.
macro_rules! ml_kem_roundtrip {
    ($ty:ty) => {{
        let (dk, ek) = <$ty>::generate_keypair();
        let (ct, k_send) = ek.encapsulate();
        let k_recv = dk.decapsulate(&ct);
        k_send == k_recv
    }};
}

/// Run `iterations` independent keygen/encapsulate/decapsulate cycles for
/// `algorithm` and report how many produced matching shared keys. A fresh
/// keypair is generated every iteration (this measures the algorithm across
/// many independent keys, not the same key reused).
pub fn run(algorithm: KemAlgorithm, iterations: usize) -> KemReport {
    let mut successes = 0;
    let mut failures = 0;
    for _ in 0..iterations {
        let ok = match algorithm {
            KemAlgorithm::MlKem512 => ml_kem_roundtrip!(MlKem512),
            KemAlgorithm::MlKem768 => ml_kem_roundtrip!(MlKem768),
            KemAlgorithm::MlKem1024 => ml_kem_roundtrip!(MlKem1024),
        };
        if ok {
            successes += 1;
        } else {
            failures += 1;
        }
    }
    KemReport {
        algorithm,
        iterations,
        successes,
        failures,
    }
}

/// Result of a classical/PQC hybrid KEM roundtrip: X25519 (ECDH) combined with
/// ML-KEM-768. The combined secret is the concatenation of both shared
/// secrets; this is illustrative for testing purposes and is not a
/// standards-track KDF combiner (e.g. RFC 9180's).
#[derive(Debug, Serialize)]
pub struct HybridKemReport {
    pub iterations: usize,
    pub successes: usize,
    pub failures: usize,
    pub combined_secret_len: usize,
}

/// Run `iterations` independent hybrid (X25519 + ML-KEM-768) roundtrips.
/// Both legs must independently agree for an iteration to count as a
/// success; see the module docs for why the combiner here is illustrative
/// rather than a standards-track KDF.
pub fn run_hybrid(iterations: usize) -> HybridKemReport {
    let mut successes = 0;
    let mut failures = 0;
    let mut combined_secret_len = 0;

    for _ in 0..iterations {
        // Classical leg: X25519 ephemeral ECDH.
        let alice_secret = x25519_dalek::EphemeralSecret::random();
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
        let bob_secret = x25519_dalek::EphemeralSecret::random();
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);
        let classical_alice = alice_secret.diffie_hellman(&bob_public);
        let classical_bob = bob_secret.diffie_hellman(&alice_public);
        let classical_ok = classical_alice.to_bytes() == classical_bob.to_bytes();

        // PQC leg: ML-KEM-768.
        let (dk, ek) = MlKem768::generate_keypair();
        let (ct, k_send) = ek.encapsulate();
        let k_recv = dk.decapsulate(&ct);
        let pq_ok = k_send == k_recv;

        if classical_ok && pq_ok {
            successes += 1;
            let mut combined = Vec::with_capacity(32 + k_send.len());
            combined.extend_from_slice(&classical_alice.to_bytes());
            combined.extend_from_slice(&k_send);
            combined_secret_len = combined.len();
        } else {
            failures += 1;
        }
    }

    HybridKemReport {
        iterations,
        successes,
        failures,
        combined_secret_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_512_roundtrip() {
        let report = run(KemAlgorithm::MlKem512, 5);
        assert!(report.all_passed());
    }

    #[test]
    fn ml_kem_768_roundtrip() {
        let report = run(KemAlgorithm::MlKem768, 5);
        assert!(report.all_passed());
    }

    #[test]
    fn ml_kem_1024_roundtrip() {
        let report = run(KemAlgorithm::MlKem1024, 5);
        assert!(report.all_passed());
    }

    #[test]
    fn hybrid_roundtrip() {
        let report = run_hybrid(5);
        assert_eq!(report.failures, 0);
        assert_eq!(report.successes, 5);
    }

    #[test]
    fn algorithm_from_str() {
        assert_eq!(
            "ml-kem-768".parse::<KemAlgorithm>().unwrap(),
            KemAlgorithm::MlKem768
        );
        assert_eq!(
            "ML_KEM_512".parse::<KemAlgorithm>().unwrap(),
            KemAlgorithm::MlKem512
        );
        assert_eq!(
            "mlkem1024".parse::<KemAlgorithm>().unwrap(),
            KemAlgorithm::MlKem1024
        );
    }

    #[test]
    fn algorithm_from_str_rejects_garbage_and_empty() {
        assert!("bogus".parse::<KemAlgorithm>().is_err());
        assert!("".parse::<KemAlgorithm>().is_err());
        assert!("ml-kem-2048".parse::<KemAlgorithm>().is_err());
    }

    #[test]
    fn zero_iterations_reports_trivially_passed_and_no_work_done() {
        // Documents current behavior rather than asserting it's ideal: 0
        // iterations means 0 successes == 0 iterations, so all_passed() is
        // true. A caller must check `iterations > 0` separately if it needs
        // to distinguish "passed" from "nothing was tested".
        let report = run(KemAlgorithm::MlKem512, 0);
        assert!(report.all_passed());
        assert_eq!(report.successes, 0);
        assert_eq!(report.failures, 0);
    }

    /// Adversarial test: a corrupted ciphertext must not decapsulate to the
    /// encapsulator's original shared key. See the module-level threat model
    /// note on implicit rejection.
    #[test]
    fn ml_kem_768_tampered_ciphertext_is_implicitly_rejected() {
        for byte_idx in [0usize, 1, 100, 500, 1087] {
            let (dk, ek) = MlKem768::generate_keypair();
            let (mut ct, k_send) = ek.encapsulate();
            let idx = byte_idx % ct.len();
            ct[idx] ^= 0xFF;
            let k_recv = dk.decapsulate(&ct);
            assert_ne!(
                k_send, k_recv,
                "tampered ciphertext (byte {idx} flipped) must not decapsulate to the original key"
            );
        }
    }

    #[test]
    fn ml_kem_768_wrong_decapsulation_key_is_rejected() {
        let (_dk_a, ek_a) = MlKem768::generate_keypair();
        let (dk_b, _ek_b) = MlKem768::generate_keypair();
        let (ct, k_send) = ek_a.encapsulate();
        // Decapsulating Alice's ciphertext with Bob's unrelated key must not
        // reproduce Alice's shared key.
        let k_wrong = dk_b.decapsulate(&ct);
        assert_ne!(k_send, k_wrong);
    }

    #[test]
    fn hybrid_hides_neither_leg_secret_incorrectly_zero() {
        // Sanity/regression guard: the combined secret must actually be the
        // concatenation length of both legs (32-byte X25519 + ML-KEM-768's
        // shared-key size), not an accidentally-truncated or empty buffer.
        let report = run_hybrid(1);
        assert_eq!(report.combined_secret_len, 32 + 32);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Property: for any byte position and any non-zero XOR mask, flipping
        /// a single byte of an ML-KEM-768 ciphertext changes the decapsulated
        /// key (implicit rejection holds across the whole ciphertext, not
        /// just at hand-picked offsets).
        #[test]
        fn ml_kem_768_any_single_byte_flip_is_rejected(byte_idx in 0usize..1088, flip in 1u8..=255) {
            let (dk, ek) = MlKem768::generate_keypair();
            let (mut ct, k_send) = ek.encapsulate();
            let idx = byte_idx % ct.len();
            ct[idx] ^= flip;
            let k_recv = dk.decapsulate(&ct);
            prop_assert_ne!(k_send, k_recv);
        }

        /// Property: ML-KEM-512/768/1024 roundtrips succeed for any small
        /// iteration count (exercises fresh randomness per proptest case,
        /// unlike the fixed-count unit tests above).
        #[test]
        fn ml_kem_roundtrip_holds_for_any_small_iteration_count(iterations in 1usize..8) {
            for algorithm in [KemAlgorithm::MlKem512, KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024] {
                prop_assert!(run(algorithm, iterations).all_passed());
            }
        }
    }
}
