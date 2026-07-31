//! Classification of known Rust crypto crates by name.
//!
//! # Honesty note
//!
//! This is a curated, name-based lookup table, not static analysis of
//! actual code usage. It answers "is a crate *named* X in the dependency
//! graph", not "does this binary actually call into cryptographic code
//! from X, and how". A crate can be present as a transitive dependency of
//! a transitive dependency, unused at runtime, or used only for an
//! unrelated non-cryptographic purpose despite the name; conversely, this
//! list is not exhaustive -- an unrecognized crate name doesn't mean "not
//! crypto", only "not in this table yet". Treat CBOM output as a lead for
//! manual review, not a certified inventory.

use serde::Serialize;

/// Coarse category for a cryptographic (or crypto-adjacent) crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoCategory {
    /// Post-quantum or classical key encapsulation / key exchange.
    KeyExchange,
    /// Digital signature schemes (post-quantum or classical).
    Signature,
    /// Symmetric ciphers (block/stream/AEAD).
    SymmetricCipher,
    /// Cryptographic hash functions.
    HashFunction,
    /// Message authentication codes.
    Mac,
    /// A protocol library that negotiates/implements a secure transport
    /// (TLS, SSH, ...), as opposed to a single primitive.
    SecureProtocol,
    /// Cryptographically secure randomness generation.
    RandomNumberGenerator,
    /// Supporting cryptographic infrastructure: constant-time comparison,
    /// zeroization, generic array/byte-array plumbing shared across
    /// multiple crypto crates, ASN.1/PEM/DER encoding, etc. Not a
    /// cryptographic primitive by itself.
    CryptoUtility,
}

/// A crate's classification, independent of which version is in use.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Classification {
    pub category: CryptoCategory,
    /// True if this crate implements or directly enables a NIST
    /// post-quantum algorithm (FIPS 203/204/205) or a classical/PQC hybrid.
    /// This does NOT mean every use of the crate is post-quantum -- e.g.
    /// `rustls` supports both classical-only and hybrid PQC handshakes;
    /// whether a given connection actually went PQC is a runtime property
    /// `scan tls` reports on, not a static fact this table can express.
    pub is_post_quantum_capable: bool,
    pub note: &'static str,
}

macro_rules! table {
    ($($name:literal => ($category:expr, $pqc:expr, $note:expr)),+ $(,)?) => {
        /// Look up a known crate name. Returns `None` for anything not in
        /// this (necessarily incomplete) table.
        pub fn classify(crate_name: &str) -> Option<Classification> {
            match crate_name {
                $($name => Some(Classification { category: $category, is_post_quantum_capable: $pqc, note: $note }),)+
                _ => None,
            }
        }
    };
}

use CryptoCategory::*;

table! {
    // --- Post-quantum (this project's own wrapped crates) ---
    "ml-kem" => (KeyExchange, true, "FIPS 203 ML-KEM (RustCrypto)"),
    "ml-dsa" => (Signature, true, "FIPS 204 ML-DSA (RustCrypto)"),
    "slh-dsa" => (Signature, true, "FIPS 205 SLH-DSA (RustCrypto)"),

    // --- Other PQC implementations seen in the wild ---
    "pqcrypto-mlkem" => (KeyExchange, true, "FIPS 203 ML-KEM (pqcrypto/PQClean bindings)"),
    "pqcrypto-mldsa" => (Signature, true, "FIPS 204 ML-DSA (pqcrypto/PQClean bindings)"),
    "pqcrypto-sphincsplus" => (Signature, true, "FIPS 205 SLH-DSA / SPHINCS+ (pqcrypto/PQClean bindings)"),
    "pqcrypto-kyber" => (KeyExchange, true, "Kyber (pre-standardization name for ML-KEM)"),
    "pqcrypto-dilithium" => (Signature, true, "Dilithium (pre-standardization name for ML-DSA)"),
    "oqs" => (KeyExchange, true, "liboqs Rust bindings (broad multi-algorithm PQC, incl. non-NIST candidates)"),
    "oqs-sys" => (KeyExchange, true, "liboqs Rust bindings (broad multi-algorithm PQC, incl. non-NIST candidates)"),
    "libcrux-ml-kem" => (KeyExchange, true, "FIPS 203 ML-KEM (Cryspen libcrux, formally verified)"),
    "libcrux-ml-dsa" => (Signature, true, "FIPS 204 ML-DSA (Cryspen libcrux, formally verified)"),

    // --- Classical key exchange ---
    "x25519-dalek" => (KeyExchange, false, "X25519 ECDH"),
    "p256" => (KeyExchange, false, "NIST P-256; also used for ECDSA"),
    "p384" => (KeyExchange, false, "NIST P-384; also used for ECDSA"),
    "hpke" => (KeyExchange, false, "Hybrid PKE (RFC 9180) -- classical only currently"),

    // --- Classical signatures ---
    "ed25519-dalek" => (Signature, false, "Ed25519"),
    "ed25519" => (Signature, false, "Ed25519 (trait/encoding crate)"),
    "ecdsa" => (Signature, false, "ECDSA (generic, paired with a curve crate)"),
    "dsa" => (Signature, false, "DSA (classical, pre-elliptic-curve)"),
    "rsa" => (Signature, false, "RSA (signatures and/or encryption)"),

    // --- Symmetric ciphers ---
    "aes" => (SymmetricCipher, false, "AES block cipher"),
    "aes-gcm" => (SymmetricCipher, false, "AES-GCM AEAD"),
    "chacha20" => (SymmetricCipher, false, "ChaCha20 stream cipher"),
    "chacha20poly1305" => (SymmetricCipher, false, "ChaCha20-Poly1305 AEAD"),
    "des" => (SymmetricCipher, false, "DES/3DES (legacy)"),

    // --- Hash functions ---
    "sha2" => (HashFunction, false, "SHA-2 family"),
    "sha3" => (HashFunction, false, "SHA-3 / SHAKE family (used by ML-KEM/ML-DSA/SLH-DSA internally)"),
    "shake" => (HashFunction, false, "SHAKE XOF (used by ML-KEM/ML-DSA/SLH-DSA internally)"),
    "sha1" => (HashFunction, false, "SHA-1 (legacy, broken for collision resistance)"),
    "md-5" => (HashFunction, false, "MD5 (legacy, broken)"),
    "blake2" => (HashFunction, false, "BLAKE2"),
    "blake3" => (HashFunction, false, "BLAKE3"),
    "keccak" => (HashFunction, false, "Keccak permutation (underlies SHA-3/SHAKE)"),

    // --- MACs ---
    "hmac" => (Mac, false, "HMAC"),

    // --- Secure transport protocol libraries ---
    "rustls" => (SecureProtocol, true, "TLS; supports ML-KEM/hybrid groups via aws-lc-rs since 0.23.x -- version-dependent, see smp-pqc-network"),
    "russh" => (SecureProtocol, true, "SSH; supports mlkem768x25519-sha256 hybrid KEX since 0.62.x -- version-dependent"),
    "quinn" => (SecureProtocol, true, "QUIC; PQC KEX depends on rustls backend version"),
    "quinn-proto" => (SecureProtocol, true, "QUIC protocol layer; PQC KEX depends on rustls backend version"),
    "openssl" => (SecureProtocol, false, "TLS (OpenSSL bindings); PQC group support is version/build-dependent and not assumed here"),
    "native-tls" => (SecureProtocol, false, "TLS (platform-native backend); PQC support depends entirely on the OS TLS stack"),

    // --- TLS supporting infrastructure ---
    "webpki-roots" => (CryptoUtility, false, "Bundled Mozilla root certificate store"),
    "rustls-webpki" => (CryptoUtility, false, "X.509 certificate validation for rustls"),
    "rustls-pki-types" => (CryptoUtility, false, "Shared PKI type definitions for the rustls ecosystem"),
    "rcgen" => (CryptoUtility, false, "Self-signed certificate generation (typically test-only)"),

    // --- General crypto providers / libraries ---
    "ring" => (CryptoUtility, false, "General-purpose crypto library (BoringSSL-derived); no PQC support"),
    "aws-lc-rs" => (CryptoUtility, true, "General-purpose crypto library (AWS-LC-derived); provides ML-KEM/hybrid groups to rustls"),

    // --- RNG ---
    "rand" => (RandomNumberGenerator, false, "General-purpose RNG facade"),
    "rand_core" => (RandomNumberGenerator, false, "RNG trait definitions"),
    "rand_chacha" => (RandomNumberGenerator, false, "ChaCha-based CSPRNG"),
    "getrandom" => (RandomNumberGenerator, false, "OS entropy source"),

    // --- Crypto-adjacent utility/plumbing crates ---
    "subtle" => (CryptoUtility, false, "Constant-time comparison primitives"),
    "zeroize" => (CryptoUtility, false, "Secret-material zeroization on drop"),
    "signature" => (CryptoUtility, false, "Shared Signer/Verifier trait definitions (RustCrypto)"),
    "digest" => (CryptoUtility, false, "Shared hash-function trait definitions (RustCrypto)"),
    "crypto-common" => (CryptoUtility, false, "Shared crypto trait definitions (RustCrypto)"),
    "cipher" => (CryptoUtility, false, "Shared cipher trait definitions (RustCrypto)"),
    "block-buffer" => (CryptoUtility, false, "Fixed-size block buffering for hash/cipher implementations"),
    "generic-array" => (CryptoUtility, false, "Const-generic-like fixed-size arrays used throughout RustCrypto"),
    "hybrid-array" => (CryptoUtility, false, "Fixed-size array plumbing used by ml-kem/ml-dsa"),
    "curve25519-dalek" => (CryptoUtility, false, "Curve25519 field/group arithmetic (underlies x25519-dalek/ed25519-dalek)"),
    "der" => (CryptoUtility, false, "DER encoding (X.509/PKCS structures)"),
    "spki" => (CryptoUtility, false, "SubjectPublicKeyInfo (X.509) encoding"),
    "pkcs8" => (CryptoUtility, false, "PKCS#8 private key encoding"),
    "pem" => (CryptoUtility, false, "PEM encoding"),
    "elliptic-curve" => (CryptoUtility, false, "Shared elliptic-curve trait definitions (RustCrypto)"),
    "const-oid" => (CryptoUtility, false, "OID constants used in X.509/PKCS encoding"),
    "tss-esapi" => (CryptoUtility, false, "TPM 2.0 TSS binding (for TEE attestation)"),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_pqc_crates_as_post_quantum() {
        for name in ["ml-kem", "ml-dsa", "slh-dsa"] {
            let c = classify(name).unwrap_or_else(|| panic!("{name} should be classified"));
            assert!(
                c.is_post_quantum_capable,
                "{name} should be flagged PQC-capable"
            );
        }
    }

    #[test]
    fn classifies_known_classical_crates_as_not_post_quantum() {
        for name in ["x25519-dalek", "ed25519-dalek", "sha2", "aes-gcm", "ring"] {
            let c = classify(name).unwrap_or_else(|| panic!("{name} should be classified"));
            assert!(
                !c.is_post_quantum_capable,
                "{name} should not be flagged PQC-capable"
            );
        }
    }

    #[test]
    fn rustls_and_russh_are_flagged_pqc_capable_but_version_dependent() {
        // These are protocol libraries where PQC support is a property of
        // the version/config in use, not an inherent property of the name
        // alone -- the note field says so explicitly; this test just checks
        // the table entries exist and are internally consistent.
        for name in ["rustls", "russh"] {
            let c = classify(name).unwrap();
            assert_eq!(c.category, CryptoCategory::SecureProtocol);
            assert!(c.is_post_quantum_capable);
            assert!(c.note.to_ascii_lowercase().contains("version"));
        }
    }

    #[test]
    fn unknown_crate_name_returns_none() {
        assert!(classify("totally-not-a-real-crate-name-xyz").is_none());
        assert!(classify("serde").is_none());
        assert!(classify("clap").is_none());
    }
}
