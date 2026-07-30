//! Signature roundtrip testing: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
//!
//! # Performance note
//!
//! SLH-DSA's hash-tree signing is orders of magnitude more hash-bound than
//! ML-DSA's lattice arithmetic, and it is unusually sensitive to whether
//! dependency code is compiled with optimizations: SLH-DSA-SHAKE-256s went
//! from ~1.8s/sign in a release build to **over two minutes/sign** in an
//! unoptimized (`cargo build`/`cargo test` default) build. The workspace
//! `Cargo.toml` sets `[profile.dev.package."*"] opt-level = 3` specifically
//! so this crate's test suite stays usable — see that comment before
//! changing dependency profile settings.
//!
//! # Statelessness
//!
//! Unlike XMSS (RFC 8391 / SP 800-208), SLH-DSA (based on SPHINCS+) is
//! stateless by design: signing does not mutate the key or consume a
//! one-time index, so there is no state-exhaustion or state-reuse hazard to
//! test for here. If/when XMSS itself is added to this kit, it will need
//! dedicated state-exhaustion and non-reuse tests that do not apply to
//! SLH-DSA.

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

/// A NIST signature parameter set: FIPS 204 ML-DSA or FIPS 205 SLH-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigAlgorithm {
    /// Security category 2 (~128-bit classical security).
    MlDsa44,
    /// Security category 3 (~192-bit classical security); NIST's recommended default.
    MlDsa65,
    /// Security category 5 (~256-bit classical security).
    MlDsa87,
    /// SLH-DSA, SHAKE hash, 128-bit security, "fast" (larger signature, quicker sign).
    SlhDsaShake128f,
    /// SLH-DSA, SHAKE hash, 128-bit security, "small" (smaller signature, slower sign).
    SlhDsaShake128s,
    SlhDsaShake192f,
    SlhDsaShake192s,
    SlhDsaShake256f,
    /// The slowest parameter set in this kit to sign under an unoptimized
    /// build — see the module-level performance note.
    SlhDsaShake256s,
    /// SLH-DSA, SHA2 hash, 128-bit security, "fast" variant.
    SlhDsaSha2128f,
    SlhDsaSha2128s,
    SlhDsaSha2192f,
    SlhDsaSha2192s,
    SlhDsaSha2256f,
    SlhDsaSha2256s,
}

impl SigAlgorithm {
    /// The canonical FIPS-style name for this parameter set, e.g. `"ML-DSA-65"`.
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

/// Run `iterations` independent keygen/sign/verify cycles for `algorithm`.
/// Each iteration also re-verifies the same signature against a one-byte-
/// tampered message and expects that to be *rejected*; `tamper_acceptances`
/// counts cases where a tampered message was wrongly accepted (should
/// always be 0 for a correct implementation). A fresh keypair is generated
/// every iteration.
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

    /// All 12 FIPS 205 parameter sets, exercised at least once. Kept to a
    /// single iteration each: the "s" (small-signature) variants, especially
    /// at 256-bit security, are extremely slow to sign even with the
    /// dependency opt-level override (see module docs) — multiplying
    /// iterations here would make the suite unpleasant to run locally for
    /// negligible extra coverage, since correctness doesn't depend on
    /// iteration count.
    #[test]
    fn slh_dsa_all_parameter_sets_roundtrip() {
        for algorithm in [
            SigAlgorithm::SlhDsaShake128f,
            SigAlgorithm::SlhDsaShake128s,
            SigAlgorithm::SlhDsaShake192f,
            SigAlgorithm::SlhDsaShake192s,
            SigAlgorithm::SlhDsaShake256f,
            SigAlgorithm::SlhDsaShake256s,
            SigAlgorithm::SlhDsaSha2128f,
            SigAlgorithm::SlhDsaSha2128s,
            SigAlgorithm::SlhDsaSha2192f,
            SigAlgorithm::SlhDsaSha2192s,
            SigAlgorithm::SlhDsaSha2256f,
            SigAlgorithm::SlhDsaSha2256s,
        ] {
            let report = run(algorithm, 1);
            assert!(
                report.all_passed(),
                "{} failed: {report:?}",
                algorithm.name()
            );
        }
    }

    #[test]
    fn algorithm_from_str_all_variants_roundtrip_through_name() {
        // Every algorithm's canonical name() must parse back to itself, and
        // every from_str match arm must be reachable -- this test would fail
        // to compile-and-pass if a new SigAlgorithm variant were added
        // without a matching name()/FromStr arm.
        for algorithm in [
            SigAlgorithm::MlDsa44,
            SigAlgorithm::MlDsa65,
            SigAlgorithm::MlDsa87,
            SigAlgorithm::SlhDsaShake128f,
            SigAlgorithm::SlhDsaShake128s,
            SigAlgorithm::SlhDsaShake192f,
            SigAlgorithm::SlhDsaShake192s,
            SigAlgorithm::SlhDsaShake256f,
            SigAlgorithm::SlhDsaShake256s,
            SigAlgorithm::SlhDsaSha2128f,
            SigAlgorithm::SlhDsaSha2128s,
            SigAlgorithm::SlhDsaSha2192f,
            SigAlgorithm::SlhDsaSha2192s,
            SigAlgorithm::SlhDsaSha2256f,
            SigAlgorithm::SlhDsaSha2256s,
        ] {
            let reparsed: SigAlgorithm = algorithm.name().parse().unwrap();
            assert_eq!(algorithm, reparsed);
        }
    }

    #[test]
    fn algorithm_from_str_rejects_garbage_and_empty() {
        assert!("bogus".parse::<SigAlgorithm>().is_err());
        assert!("".parse::<SigAlgorithm>().is_err());
        assert!("ml-dsa-99".parse::<SigAlgorithm>().is_err());
        assert!("slh-dsa-shake-512f".parse::<SigAlgorithm>().is_err());
    }

    /// Adversarial: a signature must not verify under a different signer's
    /// verifying key, even for the identical message.
    #[test]
    fn ml_dsa_65_wrong_verifying_key_is_rejected() {
        let sk_a = ml_dsa::SigningKey::<MlDsa65>::generate();
        let sk_b = ml_dsa::SigningKey::<MlDsa65>::generate();
        let sig = sk_a.sign(MESSAGE);
        assert!(sk_b.verifying_key().verify(MESSAGE, &sig).is_err());
    }

    /// Adversarial: corrupting the raw encoded signature bytes (as opposed
    /// to the message) must be rejected too -- either at decode time or at
    /// verify time. This exercises the encode/decode path that
    /// `run`/`ml_dsa_roundtrip!` never touches, since that macro only ever
    /// tampers the message.
    #[test]
    fn ml_dsa_65_corrupted_signature_bytes_are_rejected() {
        let sk = ml_dsa::SigningKey::<MlDsa65>::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(MESSAGE);
        let mut encoded = sig.encode();
        encoded[0] ^= 0xFF;
        match ml_dsa::Signature::<MlDsa65>::decode(&encoded) {
            None => {} // malformed encoding correctly rejected at decode time
            Some(tampered_sig) => {
                assert!(vk.verify(MESSAGE, &tampered_sig).is_err());
            }
        }
    }

    /// Same property for SLH-DSA, whose signature encoding is a plain byte
    /// array with a fallible `TryFrom<&[u8]>` rather than an `Option`-returning
    /// `decode`.
    #[test]
    fn slh_dsa_shake_128f_corrupted_signature_bytes_are_rejected() {
        let mut rng = rand::thread_rng();
        let sk = slh_dsa::SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();
        let sig = sk.sign_with_rng(&mut rng, MESSAGE);
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 0xFF;
        match slh_dsa::Signature::<Shake128f>::try_from(&bytes[..]) {
            Err(_) => {} // malformed encoding correctly rejected at decode time
            Ok(tampered_sig) => {
                assert!(vk.verify(MESSAGE, &tampered_sig).is_err());
            }
        }
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Property: ML-DSA-65 signs and verifies correctly for arbitrary
        /// messages, not just the fixed MESSAGE constant used elsewhere.
        #[test]
        fn ml_dsa_65_arbitrary_message_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..512)) {
            let sk = ml_dsa::SigningKey::<MlDsa65>::generate();
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);
            prop_assert!(vk.verify(&msg, &sig).is_ok());
        }

        /// Property: flipping any single byte of an arbitrary non-empty
        /// message invalidates the original signature.
        #[test]
        fn ml_dsa_65_any_single_byte_message_tamper_is_rejected(
            msg in prop::collection::vec(any::<u8>(), 1..512),
            idx in 0usize..512,
            flip in 1u8..=255,
        ) {
            let idx = idx % msg.len();
            let sk = ml_dsa::SigningKey::<MlDsa65>::generate();
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);
            let mut tampered_msg = msg.clone();
            tampered_msg[idx] ^= flip;
            prop_assert!(vk.verify(&tampered_msg, &sig).is_err());
        }
    }
}
