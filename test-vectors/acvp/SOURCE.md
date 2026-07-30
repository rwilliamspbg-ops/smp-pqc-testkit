# ACVP test vector provenance

These files are sampled subsets of NIST's own [ACVP-Server](https://github.com/usnistgov/ACVP-Server)
`internalProjection.json` test vectors — the same ground-truth files NIST's
own reference validator uses. Fetched 2026-07-30 from `master`:

| File | Source |
|---|---|
| `ml_kem_keygen.json` | `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` |
| `ml_kem_decap.json` | `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` (VAL/decapsulation groups only) |
| `ml_dsa_keygen.json` | `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json` |
| `ml_dsa_sigver.json` | `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json` (`preHash=='pure'` groups only) |
| `slh_dsa_keygen.json` | `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json` |
| `slh_dsa_sigver.json` | `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` (`preHash=='pure'` groups only) |

Each source file is much larger (tens of KB to 30+ MB) than what's checked
in here; only a sample is embedded per parameter set (see each file's own
`"note"` field for exactly how many and how they were selected) to keep this
repo's size reasonable. This is a **KAT smoke test**, not exhaustive ACVP
conformance validation — NIST's ACVP validation service, or a full run
against the un-truncated source files, is the authoritative conformance
check.

## Scope limitations

- `ml_dsa_sigver.json` / `slh_dsa_sigver.json` are restricted to
  `preHash=='pure'` test groups. Neither this test-vector set nor
  smp-pqc-core's KAT tests exercise FIPS 204/205's separate "pre-hash" (aka
  "HashML-DSA"/"HashSLH-DSA") signing mode.
- Context strings ARE included and exercised (`ml_dsa::VerifyingKey::verify_with_context`,
  `slh_dsa::VerifyingKey::try_verify_with_context`), even though
  `smp-pqc-core`'s public `sig::run()` wrapper doesn't expose a context
  parameter yet — the KAT tests call the underlying RustCrypto crates
  directly for the precision this needs (specific parameter sets, raw
  pk/sig bytes, context strings), the same way `smp-pqc-bench` does.
- `ml_kem_decap.json` only covers the VAL/decapsulation direction (an
  expanded decapsulation key + a ciphertext, some deliberately corrupted,
  checked against NIST's own expected output — including their own
  "modified ciphertext" implicit-rejection cases). The AFT/encapsulation
  direction isn't included: encapsulation KAT requires deterministically
  injecting the internal randomness `m`, which needs the `ml-kem` crate's
  `hazmat` feature and isn't wired up yet.
