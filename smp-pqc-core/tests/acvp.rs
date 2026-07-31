//! NIST ACVP known-answer tests (KATs), sampled from NIST's own
//! ACVP-Server `internalProjection.json` reference vectors -- see
//! `smp-pqc-core/test-vectors/SOURCE.md` for exactly where each file came
//! from, how it was sampled, and this test suite's scope limitations (pure
//! mode only, no prehash mode). Vectors live inside this crate's own
//! directory tree (not the workspace root) specifically so `cargo package`
//! includes them -- an `include_str!` pointing outside the crate directory
//! would compile in this workspace but fail for anyone building from the
//! published crates.io tarball.
//!
//! These call the underlying RustCrypto crates directly rather than going
//! through smp-pqc-core's `kem`/`sig` wrappers: ACVP vectors need precise
//! low-level control (specific parameter sets, raw key/ciphertext/signature
//! bytes, context strings) that those wrappers deliberately abstract away
//! for the CLI's simpler use case.
//!
//! DEPRECATED API TRACKING: This file uses `ml_kem::ExpandedKeyEncoding`,
//! `to_expanded_bytes()`, `from_expanded_bytes()`, and `ml_dsa::SigningKey::expanded_key().to_expanded()`
//! which are deprecated in ml-kem 0.3.2 / ml-dsa 0.1.1. These are used for
//! KAT validation against NIST reference vectors where we need to compare
//! exact internal key encodings. The suppression is intentional and scoped
//! to this test module. MIGRATION TODO: When ml-kem/ml-dsa provide a
//! stable, non-deprecated API for expanded key serialization/deserialization
//! (or when ACVP vectors no longer require it), remove the `#[allow(deprecated)]`
//! attributes and migrate to the new API. Track upstream at:
//! - https://github.com/RustCrypto/ML-KEM
//! - https://github.com/RustCrypto/ML-DSA

use ml_dsa::Keypair as MlDsaKeypair;
use ml_kem::kem::{Decapsulate, FromSeed, KeyExport};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{MlKem1024, MlKem512, MlKem768};
use serde::Deserialize;

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex in test vector: {e}"))
}

// ---------------------------------------------------------------- ML-KEM --

#[derive(Deserialize)]
struct MlKemKeygenFile {
    tests: Vec<MlKemKeygenCase>,
}

#[derive(Deserialize)]
struct MlKemKeygenCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: String,
    z: String,
    ek: String,
    dk: String,
}

macro_rules! check_ml_kem_keygen {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let d = hex_decode(&case.d);
        let z = hex_decode(&case.z);
        let mut seed = ml_kem::Seed::default();
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        let (dk, ek) = <$ty as FromSeed>::from_seed(&seed);
        assert_eq!(
            ek.to_bytes().as_slice(),
            hex_decode(&case.ek).as_slice(),
            "tcId {} ({}): encapsulation key mismatch",
            case.tc_id,
            case.parameter_set
        );
        #[allow(deprecated)]
        let dk_bytes = dk.to_expanded_bytes();
        assert_eq!(
            dk_bytes.as_slice(),
            hex_decode(&case.dk).as_slice(),
            "tcId {} ({}): decapsulation key mismatch",
            case.tc_id,
            case.parameter_set
        );
    }};
}

#[test]
fn ml_kem_keygen_acvp_kat() {
    let file: MlKemKeygenFile =
        serde_json::from_str(include_str!("../test-vectors/ml_kem_keygen.json")).unwrap();
    assert!(!file.tests.is_empty());
    for case in &file.tests {
        match case.parameter_set.as_str() {
            "ML-KEM-512" => check_ml_kem_keygen!(MlKem512, case),
            "ML-KEM-768" => check_ml_kem_keygen!(MlKem768, case),
            "ML-KEM-1024" => check_ml_kem_keygen!(MlKem1024, case),
            other => panic!("unexpected ML-KEM parameter set in test vectors: {other}"),
        }
    }
}

#[derive(Deserialize)]
struct MlKemDecapFile {
    tests: Vec<MlKemDecapCase>,
}

#[derive(Deserialize)]
struct MlKemDecapCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    reason: Option<String>,
    dk: String,
    c: String,
    k: String,
}

macro_rules! check_ml_kem_decap {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let dk_bytes = hex_decode(&case.dk);
        let mut expanded = ml_kem::ExpandedDecapsulationKey::<$ty>::default();
        expanded.copy_from_slice(&dk_bytes);
        #[allow(deprecated)]
        let dk =
            <ml_kem::DecapsulationKey<$ty> as ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
                .unwrap_or_else(|e| {
                    panic!(
                        "tcId {} ({}): failed to load expanded decapsulation key: {e:?}",
                        case.tc_id, case.parameter_set
                    )
                });
        let ct_bytes = hex_decode(&case.c);
        let mut ct = ml_kem::kem::Ciphertext::<$ty>::default();
        ct.copy_from_slice(&ct_bytes);
        let k = dk.decapsulate(&ct);
        assert_eq!(
            k.as_slice(),
            hex_decode(&case.k).as_slice(),
            "tcId {} ({}, reason={:?}): decapsulated shared key mismatch",
            case.tc_id,
            case.parameter_set,
            case.reason
        );
    }};
}

/// Includes NIST's own "modified ciphertext" cases: for those, `k` in the
/// vector is the *implicit-rejection* pseudorandom output (FIPS 203
/// Algorithm 18), not the original shared secret -- so this validates our
/// implicit-rejection derivation bit-for-bit against NIST's reference, a
/// stronger check than the "just assert it's different" property test in
/// `smp-pqc-core::kem`'s own test suite.
#[test]
fn ml_kem_decapsulation_acvp_kat() {
    let file: MlKemDecapFile =
        serde_json::from_str(include_str!("../test-vectors/ml_kem_decap.json")).unwrap();
    assert!(!file.tests.is_empty());
    for case in &file.tests {
        match case.parameter_set.as_str() {
            "ML-KEM-512" => check_ml_kem_decap!(MlKem512, case),
            "ML-KEM-768" => check_ml_kem_decap!(MlKem768, case),
            "ML-KEM-1024" => check_ml_kem_decap!(MlKem1024, case),
            other => panic!("unexpected ML-KEM parameter set in test vectors: {other}"),
        }
    }
}

#[derive(Deserialize)]
struct MlKemEncapFile {
    tests: Vec<MlKemEncapCase>,
}

#[derive(Deserialize)]
struct MlKemEncapCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    ek: String,
    m: String,
    c: String,
    k: String,
}

macro_rules! check_ml_kem_encap {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let ek_bytes = hex_decode(&case.ek);
        let mut ek_enc = ml_kem::kem::Key::<ml_kem::EncapsulationKey<$ty>>::default();
        ek_enc.copy_from_slice(&ek_bytes);
        let ek = ml_kem::EncapsulationKey::<$ty>::new(&ek_enc)
            .unwrap_or_else(|e| panic!("tcId {}: invalid encapsulation key: {e:?}", case.tc_id));

        let m_bytes = hex_decode(&case.m);
        let mut m = ml_kem::B32::default();
        m.copy_from_slice(&m_bytes);

        // Injects NIST's own randomness `m` instead of drawing fresh OS
        // randomness, so the ciphertext is reproducible and comparable
        // against NIST's expected `c`. `encapsulate_deterministic` is a
        // fully public method regardless of the `hazmat` Cargo feature --
        // that feature only controls whether it's *shown* in rustdoc, not
        // whether it compiles. Real callers must never do this: injecting
        // non-fresh or reused randomness here is a catastrophic security
        // failure, per the crate's own doc comment on this method.
        let (c, k) = ek.encapsulate_deterministic(&m);

        assert_eq!(
            c.as_slice(),
            hex_decode(&case.c).as_slice(),
            "tcId {} ({}): ciphertext mismatch",
            case.tc_id,
            case.parameter_set
        );
        assert_eq!(
            k.as_slice(),
            hex_decode(&case.k).as_slice(),
            "tcId {} ({}): shared key mismatch",
            case.tc_id,
            case.parameter_set
        );
    }};
}

#[test]
fn ml_kem_encapsulation_acvp_kat() {
    let file: MlKemEncapFile =
        serde_json::from_str(include_str!("../test-vectors/ml_kem_encap.json")).unwrap();
    assert!(!file.tests.is_empty());
    for case in &file.tests {
        match case.parameter_set.as_str() {
            "ML-KEM-512" => check_ml_kem_encap!(MlKem512, case),
            "ML-KEM-768" => check_ml_kem_encap!(MlKem768, case),
            "ML-KEM-1024" => check_ml_kem_encap!(MlKem1024, case),
            other => panic!("unexpected ML-KEM parameter set in test vectors: {other}"),
        }
    }
}

// ---------------------------------------------------------------- ML-DSA --

#[derive(Deserialize)]
struct MlDsaKeygenFile {
    tests: Vec<MlDsaKeygenCase>,
}

#[derive(Deserialize)]
struct MlDsaKeygenCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: String,
    pk: String,
    sk: String,
}

macro_rules! check_ml_dsa_keygen {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let seed_bytes = hex_decode(&case.seed);
        let mut seed = ml_dsa::Seed::default();
        seed.copy_from_slice(&seed_bytes);
        let sk = ml_dsa::SigningKey::<$ty>::from_seed(&seed);
        assert_eq!(
            sk.verifying_key().encode().as_slice(),
            hex_decode(&case.pk).as_slice(),
            "tcId {} ({}): public key mismatch",
            case.tc_id,
            case.parameter_set
        );
        #[allow(deprecated)]
        let sk_bytes = sk.expanded_key().to_expanded();
        assert_eq!(
            sk_bytes.as_slice(),
            hex_decode(&case.sk).as_slice(),
            "tcId {} ({}): secret key mismatch",
            case.tc_id,
            case.parameter_set
        );
    }};
}

#[test]
fn ml_dsa_keygen_acvp_kat() {
    let file: MlDsaKeygenFile =
        serde_json::from_str(include_str!("../test-vectors/ml_dsa_keygen.json")).unwrap();
    assert!(!file.tests.is_empty());
    for case in &file.tests {
        match case.parameter_set.as_str() {
            "ML-DSA-44" => check_ml_dsa_keygen!(ml_dsa::MlDsa44, case),
            "ML-DSA-65" => check_ml_dsa_keygen!(ml_dsa::MlDsa65, case),
            "ML-DSA-87" => check_ml_dsa_keygen!(ml_dsa::MlDsa87, case),
            other => panic!("unexpected ML-DSA parameter set in test vectors: {other}"),
        }
    }
}

#[derive(Deserialize)]
struct MlDsaSigVerFile {
    tests: Vec<MlDsaSigVerCase>,
}

#[derive(Deserialize)]
struct MlDsaSigVerCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    reason: Option<String>,
    pk: String,
    message: String,
    context: String,
    signature: String,
}

macro_rules! check_ml_dsa_sigver {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let pk_bytes = hex_decode(&case.pk);
        let mut pk_enc = ml_dsa::EncodedVerifyingKey::<$ty>::default();
        pk_enc.copy_from_slice(&pk_bytes);
        let vk = ml_dsa::VerifyingKey::<$ty>::decode(&pk_enc);

        let sig_bytes = hex_decode(&case.signature);
        let message = hex_decode(&case.message);
        let context = hex_decode(&case.context);

        let passed = if sig_bytes.len() == ml_dsa::EncodedSignature::<$ty>::default().len() {
            let mut sig_enc = ml_dsa::EncodedSignature::<$ty>::default();
            sig_enc.copy_from_slice(&sig_bytes);
            match ml_dsa::Signature::<$ty>::decode(&sig_enc) {
                Some(sig) => vk.verify_with_context(&message, &context, &sig),
                None => false, // malformed signature encoding: correctly not verifiable
            }
        } else {
            false // wrong-length signature: correctly not verifiable
        };

        assert_eq!(
            passed, case.test_passed,
            "tcId {} ({}, reason={:?}): verify_with_context result did not match NIST's expected testPassed",
            case.tc_id, case.parameter_set, case.reason
        );
    }};
}

/// Exercises `ml_dsa::VerifyingKey::verify_with_context` against NIST's
/// vectors, including deliberately-corrupted signatures/messages/keys where
/// `testPassed` is `false` -- adversarial coverage this kit's own
/// `sig::run()` roundtrip tests can't provide, since those only ever
/// generate their own genuine signatures.
#[test]
fn ml_dsa_sigver_acvp_kat() {
    let file: MlDsaSigVerFile =
        serde_json::from_str(include_str!("../test-vectors/ml_dsa_sigver.json")).unwrap();
    assert!(!file.tests.is_empty());
    let mut saw_pass = false;
    let mut saw_fail = false;
    for case in &file.tests {
        if case.test_passed {
            saw_pass = true;
        } else {
            saw_fail = true;
        }
        match case.parameter_set.as_str() {
            "ML-DSA-44" => check_ml_dsa_sigver!(ml_dsa::MlDsa44, case),
            "ML-DSA-65" => check_ml_dsa_sigver!(ml_dsa::MlDsa65, case),
            "ML-DSA-87" => check_ml_dsa_sigver!(ml_dsa::MlDsa87, case),
            other => panic!("unexpected ML-DSA parameter set in test vectors: {other}"),
        }
    }
    // Guards against a future edit accidentally sampling only one outcome,
    // which would silently stop testing the other branch.
    assert!(
        saw_pass,
        "test vectors should include at least one passing case"
    );
    assert!(
        saw_fail,
        "test vectors should include at least one failing case"
    );
}

// --------------------------------------------------------------- SLH-DSA --

#[derive(Deserialize)]
struct SlhDsaKeygenFile {
    tests: Vec<SlhDsaKeygenCase>,
}

#[derive(Deserialize)]
struct SlhDsaKeygenCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "skSeed")]
    sk_seed: String,
    #[serde(rename = "skPrf")]
    sk_prf: String,
    #[serde(rename = "pkSeed")]
    pk_seed: String,
    sk: String,
    pk: String,
}

macro_rules! check_slh_dsa_keygen {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let sk_seed = hex_decode(&case.sk_seed);
        let sk_prf = hex_decode(&case.sk_prf);
        let pk_seed = hex_decode(&case.pk_seed);
        let sk = slh_dsa::SigningKey::<$ty>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        assert_eq!(
            sk.to_bytes().as_slice(),
            hex_decode(&case.sk).as_slice(),
            "tcId {} ({}): secret key mismatch",
            case.tc_id,
            case.parameter_set
        );
        assert_eq!(
            sk.verifying_key().to_bytes().as_slice(),
            hex_decode(&case.pk).as_slice(),
            "tcId {} ({}): public key mismatch",
            case.tc_id,
            case.parameter_set
        );
    }};
}

#[test]
fn slh_dsa_keygen_acvp_kat() {
    use slh_dsa::signature::Keypair;
    let file: SlhDsaKeygenFile =
        serde_json::from_str(include_str!("../test-vectors/slh_dsa_keygen.json")).unwrap();
    assert!(!file.tests.is_empty());
    for case in &file.tests {
        match case.parameter_set.as_str() {
            "SLH-DSA-SHAKE-128f" => check_slh_dsa_keygen!(slh_dsa::Shake128f, case),
            "SLH-DSA-SHAKE-128s" => check_slh_dsa_keygen!(slh_dsa::Shake128s, case),
            "SLH-DSA-SHAKE-192f" => check_slh_dsa_keygen!(slh_dsa::Shake192f, case),
            "SLH-DSA-SHAKE-192s" => check_slh_dsa_keygen!(slh_dsa::Shake192s, case),
            "SLH-DSA-SHAKE-256f" => check_slh_dsa_keygen!(slh_dsa::Shake256f, case),
            "SLH-DSA-SHAKE-256s" => check_slh_dsa_keygen!(slh_dsa::Shake256s, case),
            "SLH-DSA-SHA2-128f" => check_slh_dsa_keygen!(slh_dsa::Sha2_128f, case),
            "SLH-DSA-SHA2-128s" => check_slh_dsa_keygen!(slh_dsa::Sha2_128s, case),
            "SLH-DSA-SHA2-192f" => check_slh_dsa_keygen!(slh_dsa::Sha2_192f, case),
            "SLH-DSA-SHA2-192s" => check_slh_dsa_keygen!(slh_dsa::Sha2_192s, case),
            "SLH-DSA-SHA2-256f" => check_slh_dsa_keygen!(slh_dsa::Sha2_256f, case),
            "SLH-DSA-SHA2-256s" => check_slh_dsa_keygen!(slh_dsa::Sha2_256s, case),
            other => panic!("unexpected SLH-DSA parameter set in test vectors: {other}"),
        }
    }
}

#[derive(Deserialize)]
struct SlhDsaSigVerFile {
    tests: Vec<SlhDsaSigVerCase>,
}

#[derive(Deserialize)]
struct SlhDsaSigVerCase {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    reason: Option<String>,
    pk: String,
    message: String,
    context: String,
    signature: String,
}

macro_rules! check_slh_dsa_sigver {
    ($ty:ty, $case:expr) => {{
        let case = $case;
        let pk_bytes = hex_decode(&case.pk);
        let message = hex_decode(&case.message);
        let context = hex_decode(&case.context);
        let sig_bytes = hex_decode(&case.signature);

        let passed = match slh_dsa::VerifyingKey::<$ty>::try_from(pk_bytes.as_slice()) {
            Ok(vk) => match slh_dsa::Signature::<$ty>::try_from(sig_bytes.as_slice()) {
                Ok(sig) => vk.try_verify_with_context(&message, &context, &sig).is_ok(),
                Err(_) => false, // malformed signature encoding: correctly not verifiable
            },
            Err(_) => false, // malformed public key encoding: correctly not verifiable
        };

        assert_eq!(
            passed, case.test_passed,
            "tcId {} ({}, reason={:?}): try_verify_with_context result did not match NIST's expected testPassed",
            case.tc_id, case.parameter_set, case.reason
        );
    }};
}

/// See [`ml_dsa_sigver_acvp_kat`] for the rationale; same idea for SLH-DSA.
#[test]
fn slh_dsa_sigver_acvp_kat() {
    let file: SlhDsaSigVerFile =
        serde_json::from_str(include_str!("../test-vectors/slh_dsa_sigver.json")).unwrap();
    assert!(!file.tests.is_empty());
    let mut saw_pass = false;
    let mut saw_fail = false;
    for case in &file.tests {
        if case.test_passed {
            saw_pass = true;
        } else {
            saw_fail = true;
        }
        match case.parameter_set.as_str() {
            "SLH-DSA-SHAKE-128f" => check_slh_dsa_sigver!(slh_dsa::Shake128f, case),
            "SLH-DSA-SHAKE-128s" => check_slh_dsa_sigver!(slh_dsa::Shake128s, case),
            "SLH-DSA-SHAKE-192f" => check_slh_dsa_sigver!(slh_dsa::Shake192f, case),
            "SLH-DSA-SHAKE-192s" => check_slh_dsa_sigver!(slh_dsa::Shake192s, case),
            "SLH-DSA-SHAKE-256f" => check_slh_dsa_sigver!(slh_dsa::Shake256f, case),
            "SLH-DSA-SHAKE-256s" => check_slh_dsa_sigver!(slh_dsa::Shake256s, case),
            "SLH-DSA-SHA2-128f" => check_slh_dsa_sigver!(slh_dsa::Sha2_128f, case),
            "SLH-DSA-SHA2-128s" => check_slh_dsa_sigver!(slh_dsa::Sha2_128s, case),
            "SLH-DSA-SHA2-192f" => check_slh_dsa_sigver!(slh_dsa::Sha2_192f, case),
            "SLH-DSA-SHA2-192s" => check_slh_dsa_sigver!(slh_dsa::Sha2_192s, case),
            "SLH-DSA-SHA2-256f" => check_slh_dsa_sigver!(slh_dsa::Sha2_256f, case),
            "SLH-DSA-SHA2-256s" => check_slh_dsa_sigver!(slh_dsa::Sha2_256s, case),
            other => panic!("unexpected SLH-DSA parameter set in test vectors: {other}"),
        }
    }
    assert!(
        saw_pass,
        "test vectors should include at least one passing case"
    );
    assert!(
        saw_fail,
        "test vectors should include at least one failing case"
    );
}
