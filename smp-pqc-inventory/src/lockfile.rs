//! Parsing of `Cargo.lock` files -- the actual resolved dependency graph
//! (exact versions), rather than `Cargo.toml`'s version *requirements*. A
//! CBOM should reflect what's actually compiled in, so the lockfile is the
//! right source of truth.

use serde::Deserialize;
use std::path::Path;

/// One resolved dependency from a `Cargo.lock` file.
#[derive(Debug, Clone, Deserialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    #[allow(dead_code)] // kept for potential future use (e.g. flagging non-crates.io sources)
    pub source: Option<String>,
}

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default, rename = "package")]
    packages: Vec<LockedPackage>,
}

/// Parse a `Cargo.lock` file at `path` into its resolved package list.
pub fn parse_lockfile(path: &Path) -> anyhow::Result<Vec<LockedPackage>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    let parsed: CargoLock = toml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("failed to parse {} as Cargo.lock: {e}", path.display()))?;
    Ok(parsed.packages)
}

/// Given either a directory (containing `Cargo.lock`) or a direct path to a
/// lockfile, resolve the actual file path to parse.
pub fn resolve_lockfile_path(input: &Path) -> anyhow::Result<std::path::PathBuf> {
    if input.is_dir() {
        let candidate = input.join("Cargo.lock");
        if !candidate.exists() {
            anyhow::bail!(
                "no Cargo.lock found in {} -- run `cargo generate-lockfile` first, or point \
                 directly at a Cargo.lock file",
                input.display()
            );
        }
        Ok(candidate)
    } else {
        Ok(input.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real, complex Cargo.lock snapshot (not a synthetic fixture) bundled
    // inside this crate's own directory tree, rather than reached via a
    // `../` path into the parent workspace: this crate must remain
    // self-contained to publish correctly (a path escaping the crate
    // directory works fine in this workspace but breaks for anyone testing
    // the crate from its published crates.io tarball, which only contains
    // files under the crate root).
    const SAMPLE_LOCKFILE: &str = include_str!("../tests/fixtures/sample-workspace-cargo-lock.txt");

    #[test]
    fn parses_a_real_complex_lockfile() {
        // Exercises the parser against real-world data (path deps, registry
        // deps, deps with/without `source`), not just a minimal fixture.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Cargo.lock");
        std::fs::write(&path, SAMPLE_LOCKFILE).expect("write fixture");

        let packages = parse_lockfile(&path).expect("parse sample Cargo.lock");
        assert!(packages.len() > 20, "expected a real, non-trivial lockfile");
        assert!(packages.iter().any(|p| p.name == "ml-kem"));
        assert!(packages.iter().any(|p| p.name == "rustls"));
    }

    #[test]
    fn resolve_lockfile_path_finds_cargo_lock_in_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("Cargo.lock"), SAMPLE_LOCKFILE).expect("write fixture");

        let resolved = resolve_lockfile_path(dir.path()).expect("resolve");
        assert!(resolved.ends_with("Cargo.lock"));
        assert!(resolved.exists());
    }

    #[test]
    fn resolve_lockfile_path_rejects_directory_without_lockfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_lockfile_path(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn resolve_lockfile_path_passes_through_a_direct_file_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("some-other-name.lock");
        std::fs::write(&path, SAMPLE_LOCKFILE).expect("write fixture");

        let resolved = resolve_lockfile_path(&path).expect("resolve");
        assert_eq!(resolved, path);
    }
}
