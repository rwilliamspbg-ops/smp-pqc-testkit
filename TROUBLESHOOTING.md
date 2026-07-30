# Troubleshooting Guide

This document provides solutions to common issues encountered when using the SMP-PQC-Testkit.

## Installation Issues

### Rust Toolchain Not Found
**Problem:** `command not found: rustc` or similar errors when trying to run cargo commands.

**Solution:** Install the Rust toolchain using rustup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Dependency Conflicts
**Problem:** Cargo reports version conflicts when building.

**Solution:** Try cleaning the build cache and rebuilding:
```bash
cargo clean
cargo build --workspace
```

If issues persist, try with a fresh checkout:
```bash
git clean -xfd
cargo build --workspace
```

## Build Issues

### Compilation Errors in Dependencies
**Problem:** Errors occur while compiling dependencies like `ml-kem`, `ml-dsa`, or `slh-dsa`.

**Solution:** 
1. Ensure you're using a supported Rust version (stable or later as specified in Cargo.toml)
2. Try updating your Rust toolchain:
   ```bash
   rustup update
   ```
3. If the issue persists, check the specific dependency's issue tracker for known issues.

### Linking Errors on Windows
**Problem:** Linker errors when building on Windows, particularly with cryptographic dependencies.

**Solution:**
1. Ensure you have the Visual Studio Build Tools installed with the C++ workload
2. Try using the GNU toolchain instead of MSVC:
   ```bash
   rustup toolchain install stable-gnu
   rustup default stable-gnu
   ```

## Testing Issues

### Tests Hanging or Timing Out
**Problem:** Tests hang or exceed time limits, particularly constant-time tests or network scanning tests.

**Solution:**
1. For constant-time tests (`dudect_ml_kem_decap`): These require a quiet system to run accurately. Close other applications and consider running with `--release` flag.
2. For network scanning tests: These require network access and may fail in restricted environments. Ensure you have permission to scan the target hosts.
3. Increase timeout for specific tests if needed:
   ```bash
   cargo test --test test_name -- --test-threads=1 --timeout 120s
   ```

### Constant-Time Test Failures
**Problem:** The `dudect_ml_kem_decap` example shows timing leaks.

**Solution:**
1. Remember that a single test cannot prove constant-time behavior - it only checks for leaks under specific conditions.
2. Try running with more samples:
   ```bash
   cargo run -p smp-pqc-core --release --example dudect_ml_kem_decap -- --samples 500000
   ```
3. Ensure you're running on a relatively quiet system - virtualized or shared environments can introduce noise.
4. Consider that some variance is expected due to CPU frequency scaling, caching, etc.

## Usage Issues

### CLI Command Not Found
**Problem:** `smp-pqc` command not found after installation.

**Solution:**
1. Ensure the cargo bin directory is in your PATH:
   ```bash
   echo $PATH  # Should include ~/.cargo/bin on Unix or %USERPATH%\.cargo\bin on Windows
   ```
2. If installed via cargo install, reinstall to ensure binaries are placed correctly:
   ```bash
   cargo install --path smp-pqc-cli
   ```

### Network Scanning Permissions Errors
**Problem:** `smp-pqc scan tls` or `smp-pqc scan ssh` fails with permission errors.

**Solution:**
1. For TLS scanning: You may need elevated privileges to bind to certain ports or access network interfaces on some systems.
2. For SSH scanning: Ensure you have network access to the target port (usually 22).
3. Try running with administrator/root privileges if necessary (though prefer least privilege):
   ```bash
   # On Unix-like systems
   sudo smp-pqc scan tls example.com
   
   # On Windows, run Command Prompt or PowerShell as Administrator
   ```

### Invalid Algorithm Names
**Problem:** Error when specifying algorithm names like "ml-kem-768".

**Solution:**
1. Check the list of supported algorithms in the documentation or by running:
   ```bash
   smp-pqc test kem --help
   smp-pqc test sig --help
   ```
2. Ensure you're using the exact algorithm names as specified (case-sensitive):
   - KEM: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`
   - Signature: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `slh-dsa-{shake,sha2}-{128,192,256}{f,s}`

## Performance Issues

### Slow Benchmark Results
**Problem:** Benchmark results seem unexpectedly slow, particularly for SLH-DSA.

**Solution:**
1. SLH-DSA "s" (short) variants are intentionally slower - this is expected behavior.
2. Ensure you're running benchmarks in release mode:
   ```bash
   cargo bench -p smp-pqc-bench --bench kem
   cargo bench -p smp-pqc-bench --bench sig
   ```
3. Consider that debug builds are significantly slower for cryptographic operations, especially SLH-DSA.

### High Memory Usage
**Problem:** Application uses more memory than expected.

**Solution:**
1. Some PQC algorithms, particularly hash-based signatures like SLH-DSA, have higher memory requirements.
2. Check if you're running many concurrent operations - consider batching or limiting concurrency.
3. For embedded or constrained environments, consider using the more memory-efficient variants (e.g., ML-KEM-512 instead of ML-KEM-1024).

## Development Issues

### Failing to Build Documentation
**Problem:** `cargo doc` fails or produces empty documentation.

**Solution:**
1. Ensure all dependencies are available and can be downloaded.
2. Try with network enabled if you're offline:
   ```bash
   cargo doc --no-deps  # Document only this crate
   ```
3. Check for missing documentation comments in public API.

### Issues with Formal Verification (Lean 4)
**Problem:** Lean 4 verification fails or `lake build` encounters errors.

**Solution:**
1. Ensure you have a working Lean 4 toolchain installed via elan:
   ```bash
   curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y
   ```
2. Update your toolchain:
   ```bash
   lake update
   ```
3. Clean and rebuild:
   ```bash
   lake clean
   lake build
   ```
4. Check the Lean 4 documentation for version-specific issues.

## Getting Further Help

If you've checked this guide and still encounter issues:

1. Check the [GitHub Issues](https://github.com/rwilliamspbg-ops/smp-pqc-testkit/issues) for similar problems
2. Search for error messages in the project's documentation
3. Consider reaching out to the maintainers with:
   - Detailed steps to reproduce
   - Exact error messages
   - Your environment (OS, Rust version, hardware)
   - Relevant logs or output

Remember to check if your issue has already been reported before opening a new issue.