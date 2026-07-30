//! Key Encapsulation Mechanism roundtrip testing: ML-KEM (FIPS 203) and an
//! X25519 + ML-KEM-768 classical/PQC hybrid.

use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{MlKem1024, MlKem512, MlKem768};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl KemAlgorithm {
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
        assert!("bogus".parse::<KemAlgorithm>().is_err());
    }
}
