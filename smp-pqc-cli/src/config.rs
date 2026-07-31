use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct CliConfig {
    /// Default number of iterations for test commands
    pub iterations: Option<usize>,
    /// Default report format (text or json)
    pub report: Option<String>,
    /// Default connection timeout in seconds for scan commands
    pub timeout_secs: Option<u64>,
    /// Only show PQC/hybrid results for scan commands
    pub pqc_only: Option<bool>,
    /// Skip certificate validation for TLS scans
    pub insecure: Option<bool>,
    /// Output file for inventory command
    pub output: Option<String>,
    /// Emit CBOM format for inventory command
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
