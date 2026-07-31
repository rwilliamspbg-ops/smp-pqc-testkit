use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// `pqc_only`/`insecure`/`cbom` are read from a config file but currently
/// have no effect: their CLI counterparts are plain `bool` flags (presence
/// = true, absence = false via clap's flag `ArgAction`), so the caller
/// always passes `Some(false)` into `merge_with_cli` even when the flag was
/// never typed, permanently shadowing whatever's here. Fixing that means
/// deciding on a different CLI syntax for these three flags (e.g.
/// `--cbom <true|false>` instead of a bare `--cbom`), which is a real UX
/// change, not a bugfix -- left as-is for now. `iterations`/`report`/
/// `timeout_secs`/`output` don't have this problem (their CLI flags always
/// take an explicit value already) and do work end-to-end -- see
/// smp-pqc-cli/tests/cli.rs's `config_file_*` tests.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct CliConfig {
    /// Default number of iterations for test commands
    pub iterations: Option<usize>,
    /// Default report format (text or json)
    pub report: Option<String>,
    /// Default connection timeout in seconds for scan commands
    pub timeout_secs: Option<u64>,
    /// Only show PQC/hybrid results for scan commands. Currently inert -- see struct docs.
    pub pqc_only: Option<bool>,
    /// Skip certificate validation for TLS scans. Currently inert -- see struct docs.
    pub insecure: Option<bool>,
    /// Output file for inventory command
    pub output: Option<String>,
    /// Emit CBOM format for inventory command. Currently inert -- see struct docs.
    pub cbom: Option<bool>,
}

impl CliConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {}", path.display(), e))?;
        let config: CliConfig = toml::from_str(&content).map_err(|e| {
            anyhow::anyhow!("failed to parse config file {}: {}", path.display(), e)
        })?;
        Ok(config)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn merge_with_cli(
        &self,
        cli_iterations: Option<usize>,
        cli_report: Option<String>,
        cli_timeout: Option<u64>,
        cli_pqc_only: Option<bool>,
        cli_insecure: Option<bool>,
        cli_output: Option<String>,
        cli_cbom: Option<bool>,
    ) -> MergedConfig {
        MergedConfig {
            iterations: cli_iterations.or(self.iterations).unwrap_or(1000),
            report: cli_report
                .or(self.report.clone())
                .unwrap_or_else(|| "text".to_string()),
            timeout_secs: cli_timeout.or(self.timeout_secs).unwrap_or(10),
            pqc_only: cli_pqc_only.or(self.pqc_only).unwrap_or(false),
            insecure: cli_insecure.or(self.insecure).unwrap_or(false),
            output: cli_output.or(self.output.clone()),
            cbom: cli_cbom.or(self.cbom).unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MergedConfig {
    pub iterations: usize,
    pub report: String,
    pub timeout_secs: u64,
    pub pqc_only: bool,
    pub insecure: bool,
    pub output: Option<String>,
    pub cbom: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Writes `content` to a uniquely-named temp file and returns its path.
    /// Uses the test's own name (via `#[test] fn` + a suffix) to avoid
    /// collisions when tests run in parallel.
    fn write_temp_toml(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("smp-pqc-cli-config-test-{name}.toml"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn load_parses_a_valid_config_file() {
        let path = write_temp_toml(
            "valid",
            r#"
            iterations = 42
            report = "json"
            timeout_secs = 5
            pqc_only = true
            insecure = false
            output = "out.json"
            cbom = true
            "#,
        );
        let config = CliConfig::load(&path).expect("valid TOML should load");
        assert_eq!(config.iterations, Some(42));
        assert_eq!(config.report.as_deref(), Some("json"));
        assert_eq!(config.timeout_secs, Some(5));
        assert_eq!(config.pqc_only, Some(true));
        assert_eq!(config.insecure, Some(false));
        assert_eq!(config.output.as_deref(), Some("out.json"));
        assert_eq!(config.cbom, Some(true));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_fails_clearly_on_missing_file() {
        let path = std::env::temp_dir().join("smp-pqc-cli-config-test-does-not-exist.toml");
        std::fs::remove_file(&path).ok();
        let err = CliConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("failed to read config file"));
    }

    #[test]
    fn load_fails_clearly_on_invalid_toml() {
        let path = write_temp_toml("invalid", "this is not { valid toml =");
        let err = CliConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("failed to parse config file"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn merge_with_cli_prefers_cli_values_over_config_file_values() {
        let config = CliConfig {
            iterations: Some(100),
            report: Some("text".to_string()),
            ..Default::default()
        };
        let merged = config.merge_with_cli(
            Some(7),
            Some("json".to_string()),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(merged.iterations, 7);
        assert_eq!(merged.report, "json");
    }

    #[test]
    fn merge_with_cli_falls_back_to_config_file_then_hardcoded_defaults() {
        let config = CliConfig {
            iterations: Some(100),
            ..Default::default()
        };
        let merged = config.merge_with_cli(None, None, None, None, None, None, None);
        assert_eq!(merged.iterations, 100); // from config file
        assert_eq!(merged.report, "text"); // hardcoded default
        assert_eq!(merged.timeout_secs, 10); // hardcoded default
        assert!(!merged.pqc_only);
        assert!(!merged.insecure);
        assert!(!merged.cbom);
    }
}
