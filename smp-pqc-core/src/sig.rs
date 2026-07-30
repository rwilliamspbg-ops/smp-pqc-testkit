//! Signature roundtrip testing: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).

use ml_dsa::{
    Generate, Keypair as MlDsaKeypair, MlDsa44, MlDsa65, MlDsa87, Signer as MlDsaSigner,
    Verifier as MlDsaVerifier,
};
use serde::{Deserialize, Serialize};
use slh_dsa::signature::{Keypair, RandomizedSigner, Verifier as SlhDsaVerifier};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaShake128f,
    SlhDsaShake128s,
    SlhDsaShake192f,
    SlhDsaShake192s,
    SlhDsaShake256f,
    SlhDsaShake256s,
    SlhDsaSha2128f,
    SlhDsaSha2128s,
    SlhDsaSha2192f,
    SlhDsaSha2192s,
    SlhDsaSha2256f,
    SlhDsaSha2256s,
}

impl SigAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            SigAlgorithm::MlDsa44 => "ML-DSA-44",
            SigAlgorithm::MlDsa65 => "ML-DSA-65",
            SigAlgorithm::MlDsa87 => "ML-DSA-87",
            SigAlgorithm::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            SigAlgorithm::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            SigAlgorithm::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            SigAlgorithm::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            SigAlgorithm::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
            SigAlgorithm::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            SigAlgorithm::SlhDsaSha2128f => "SLH-DSA-SHA2-128f",
            SigAlgorithm::SlhDsaSha2128s => "SLH-DSA-SHA2-128s",
            SigAlgorithm::SlhDsaSha2192f => "SLH-DSA-SHA2-192f",
            SigAlgorithm::SlhDsaSha2192s => "SLH-DSA-SHA2-192s",
            SigAlgorithm::SlhDsaSha2256f => "SLH-DSA-SHA2-256f",
            SigAlgorithm::SlhDsaSha2256s => "SLH-DSA-SHA2-256s",
        }
    }
}

impl std::str::FromStr for SigAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "ml-dsa-44" | "mldsa44" => Ok(SigAlgorithm::MlDsa44),
            "ml-dsa-65" | "mldsa65" => Ok(SigAlgorithm::MlDsa65),
            "ml-dsa-87" | "mldsa87" => Ok(SigAlgorithm::MlDsa87),
            "slh-dsa-shake-128f" => Ok(SigAlgorithm::SlhDsaShake128f),
            "slh-dsa-shake-128s" => Ok(SigAlgorithm::SlhDsaShake128s),
            "slh-dsa-shake-192f" => Ok(SigAlgorithm::SlhDsaShake192f),
            "slh-dsa-shake-192s" => Ok(SigAlgorithm::SlhDsaShake192s),
            "slh-dsa-shake-256f" => Ok(SigAlgorithm::SlhDsaShake256f),
            "slh-dsa-shake-256s" => Ok(SigAlgorithm::SlhDsaShake256s),
            "slh-dsa-sha2-128f" => Ok(SigAlgorithm::SlhDsaSha2128f),
            "slh-dsa-sha2-128s" => Ok(SigAlgorithm::SlhDsaSha2128s),
            "slh-dsa-sha2-192f" => Ok(SigAlgorithm::SlhDsaSha2192f),
            "slh-dsa-sha2-192s" => Ok(SigAlgorithm::SlhDsaSha2192s),
            "slh-dsa-sha2-256f" => Ok(SigAlgorithm::SlhDsaSha2256f),
            "slh-dsa-sha2-256s" => Ok(SigAlgorithm::SlhDsaSha2256s),
            other => Err(anyhow::anyhow!("unknown signature algorithm: {other}")),
        }
    }
}

/// Result of `iterations` independent keygen/sign/verify cycles, each of
/// which also checks that a tampered message is rejected.
#[derive(Debug, Serialize)]
pub struct SigReport {
    pub algorithm: SigAlgorithm,
    pub iterations: usize,
    pub verify_successes: usize,
    pub verify_failures: usize,
    pub tamper_rejections: usize,
    pub tamper_acceptances: usize,
}

impl SigReport {
    /// True only if every genuine signature verified AND every tampered
    /// message was correctly rejected.
    pub fn all_passed(&self) -> bool {
        self.verify_failures == 0 && self.tamper_acceptances == 0
    }
}

const MESSAGE: &[u8] = b"smp-pqc-testkit signature roundtrip";

fn tampered(message: &[u8]) -> Vec<u8> {
    let mut m = message.to_vec();
    m.push(0xFF);
    m
}

macro_rules! ml_dsa_roundtrip {
    ($ty:ty) => {{
        let sk = ml_dsa::SigningKey::<$ty>::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(MESSAGE);
        let verifies = vk.verify(MESSAGE, &sig).is_ok();
        let rejects_tamper = vk.verify(&tampered(MESSAGE), &sig).is_err();
        (verifies, rejects_tamper)
    }};
}

macro_rules! slh_dsa_roundtrip {
    ($ty:ty) => {{
        let mut rng = rand::thread_rng();
        let sk = slh_dsa::SigningKey::<$ty>::new(&mut rng);
        let vk = sk.verifying_key();
        let sig = sk.sign_with_rng(&mut rng, MESSAGE);
        let verifies = vk.verify(MESSAGE, &sig).is_ok();
        let rejects_tamper = vk.verify(&tampered(MESSAGE), &sig).is_err();
        (verifies, rejects_tamper)
    }};
}

pub fn run(algorithm: SigAlgorithm, iterations: usize) -> SigReport {
    let mut verify_successes = 0;
    let mut verify_failures = 0;
    let mut tamper_rejections = 0;
    let mut tamper_acceptances = 0;

    for _ in 0..iterations {
        let (verifies, rejects_tamper) = match algorithm {
            SigAlgorithm::MlDsa44 => ml_dsa_roundtrip!(MlDsa44),
            SigAlgorithm::MlDsa65 => ml_dsa_roundtrip!(MlDsa65),
            SigAlgorithm::MlDsa87 => ml_dsa_roundtrip!(MlDsa87),
            SigAlgorithm::SlhDsaShake128f => slh_dsa_roundtrip!(Shake128f),
            SigAlgorithm::SlhDsaShake128s => slh_dsa_roundtrip!(Shake128s),
            SigAlgorithm::SlhDsaShake192f => slh_dsa_roundtrip!(Shake192f),
            SigAlgorithm::SlhDsaShake192s => slh_dsa_roundtrip!(Shake192s),
            SigAlgorithm::SlhDsaShake256f => slh_dsa_roundtrip!(Shake256f),
            SigAlgorithm::SlhDsaShake256s => slh_dsa_roundtrip!(Shake256s),
            SigAlgorithm::SlhDsaSha2128f => slh_dsa_roundtrip!(Sha2_128f),
            SigAlgorithm::SlhDsaSha2128s => slh_dsa_roundtrip!(Sha2_128s),
            SigAlgorithm::SlhDsaSha2192f => slh_dsa_roundtrip!(Sha2_192f),
            SigAlgorithm::SlhDsaSha2192s => slh_dsa_roundtrip!(Sha2_192s),
            SigAlgorithm::SlhDsaSha2256f => slh_dsa_roundtrip!(Sha2_256f),
            SigAlgorithm::SlhDsaSha2256s => slh_dsa_roundtrip!(Sha2_256s),
        };

        if verifies {
            verify_successes += 1;
        } else {
            verify_failures += 1;
        }
        if rejects_tamper {
            tamper_rejections += 1;
        } else {
            tamper_acceptances += 1;
        }
    }

    SigReport {
        algorithm,
        iterations,
        verify_successes,
        verify_failures,
        tamper_rejections,
        tamper_acceptances,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_44_roundtrip() {
        assert!(run(SigAlgorithm::MlDsa44, 3).all_passed());
    }

    #[test]
    fn ml_dsa_65_roundtrip() {
        assert!(run(SigAlgorithm::MlDsa65, 3).all_passed());
    }

    #[test]
    fn ml_dsa_87_roundtrip() {
        assert!(run(SigAlgorithm::MlDsa87, 3).all_passed());
    }

    #[test]
    fn slh_dsa_shake_128f_roundtrip() {
        assert!(run(SigAlgorithm::SlhDsaShake128f, 2).all_passed());
    }

    #[test]
    fn slh_dsa_sha2_128s_roundtrip() {
        assert!(run(SigAlgorithm::SlhDsaSha2128s, 1).all_passed());
    }

    #[test]
    fn algorithm_from_str() {
        assert_eq!(
            "ml-dsa-65".parse::<SigAlgorithm>().unwrap(),
            SigAlgorithm::MlDsa65
        );
        assert!("bogus".parse::<SigAlgorithm>().is_err());
    }
}
