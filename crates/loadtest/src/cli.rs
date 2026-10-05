//! CLI spelling, duration syntax and conversion into shared configuration.
use aegaeon_loadtest::{LoadTestConfig, TestScenario};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "aegaeon-loadtest")]
#[command(about = "Load testing tool for Aegaeon identity provider", long_about = None)]
pub(super) struct Args {
    /// Target server URL
    #[arg(short, long, default_value = "http://localhost:8080")]
    pub(super) url: String,

    /// Canonical HTTPS issuer expected in public discovery metadata
    #[arg(long)]
    pub(super) discovery_expected_issuer: Option<String>,

    /// Number of concurrent workers (alias for users)
    #[arg(short, long, default_value_t = 10)]
    pub(super) workers: usize,

    /// Number of concurrent users (alias for workers)
    #[arg(long, alias = "users")]
    pub(super) users: Option<usize>,

    /// Test duration in seconds
    #[arg(short, long, default_value_t = 60)]
    pub(super) duration: u64,

    /// Test duration (alternative format, e.g., "60s", "5m")
    #[arg(long = "run-time", alias = "run_time")]
    pub(super) run_time: Option<String>,

    /// Target scenario invocations per second
    #[arg(short, long, default_value_t = 100.0)]
    pub(super) rps: f64,

    /// Spawn rate (users per second) - alias for rps
    #[arg(long = "spawn-rate", alias = "spawn_rate")]
    pub(super) spawn_rate: Option<f64>,

    /// Warmup duration: numeric seconds or a duration such as 10s or 1m
    #[arg(long, default_value = "10")]
    pub(super) warmup: String,

    /// Report output file (JSON format)
    #[arg(long = "report-file", alias = "report_file", required = true)]
    pub(super) report_file: String,

    /// Report UUID chosen by an independent driver before launch
    #[arg(long)]
    pub(super) report_id: Option<uuid::Uuid>,

    /// Test scenario
    #[arg(short, long, value_enum, default_value = "smoke")]
    pub(super) scenario: CliScenario,

    /// Enable debug logging
    #[arg(long)]
    pub(super) debug: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub(super) enum CliScenario {
    Smoke,
    AuthCode,
    Introspection,
    Revocation,
    Dpop,
    Userinfo,
    Discovery,
    Jwks,
    Par,
    Mixed,
    PolicyMixed,
    KeyRotation,
}

impl From<CliScenario> for TestScenario {
    fn from(cli: CliScenario) -> Self {
        match cli {
            CliScenario::Smoke => TestScenario::Smoke,
            CliScenario::AuthCode => TestScenario::AuthorizationCode,
            CliScenario::Introspection => TestScenario::Introspection,
            CliScenario::Revocation => TestScenario::Revocation,
            CliScenario::Dpop => TestScenario::DPoP,
            CliScenario::Userinfo => TestScenario::Userinfo,
            CliScenario::Discovery => TestScenario::Discovery,
            CliScenario::Jwks => TestScenario::Jwks,
            CliScenario::Par => TestScenario::PAR,
            CliScenario::Mixed => TestScenario::Mixed,
            CliScenario::PolicyMixed => TestScenario::PolicyMixed,
            CliScenario::KeyRotation => TestScenario::KeyRotation,
        }
    }
}

impl Args {
    pub(super) fn config(&self) -> Result<LoadTestConfig> {
        let duration = self
            .run_time
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .unwrap_or(Duration::from_secs(self.duration));
        let warmup_duration = parse_duration(&self.warmup)
            .map_err(|error| anyhow::anyhow!("invalid warmup: {error}"))?;
        Ok(LoadTestConfig {
            target_url: self.url.clone(),
            discovery_expected_issuer: self.discovery_expected_issuer.clone(),
            workers: self.users.unwrap_or(self.workers),
            duration,
            target_rps: self.spawn_rate.unwrap_or(self.rps),
            warmup_duration,
            scenario: self.scenario.clone().into(),
            debug: self.debug,
        })
    }
}

pub(super) fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    ensure!(!value.is_empty(), "empty duration");
    if let Ok(seconds) = value.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let position = value.char_indices().last().context("empty duration")?.0;
    let (number, unit) = value.split_at(position);
    let count: u64 = number.parse().context("invalid duration number")?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => anyhow::bail!("unknown duration unit"),
    };
    Ok(Duration::from_secs(
        count.checked_mul(multiplier).context("duration overflow")?,
    ))
}
