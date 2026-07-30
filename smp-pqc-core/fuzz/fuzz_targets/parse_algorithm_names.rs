//! Fuzz target for `KemAlgorithm::from_str` and `SigAlgorithm::from_str`.
//!
//! Scope note: this is intentionally a narrow fuzz target. smp-pqc-core does
//! not yet expose byte-level (de)serialization of keys, ciphertexts, or
//! signatures -- `run()`/`run_hybrid()` generate and consume everything
//! in-process -- so there is no encode/decode boundary to fuzz for the
//! actual crypto yet. What *is* fuzzable today is the untrusted-string
//! surface: both `FromStr` impls take arbitrary CLI/config input and must
//! never panic, allocate unboundedly, or loop, regardless of what garbage
//! is thrown at them. When smp-pqc-core grows a public byte-serialization
//! API (e.g. for CBOM or key export in a later phase), that will need its
//! own fuzz target -- this one does not cover it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use smp_pqc_core::kem::KemAlgorithm;
use smp_pqc_core::sig::SigAlgorithm;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic; a parse failure is a normal, expected Err.
        let _ = s.parse::<KemAlgorithm>();
        let _ = s.parse::<SigAlgorithm>();
    }
});
