//! Shared execution and report-witness configuration invariants.
use anyhow::{ensure, Context, Result};
use std::time::Duration;

/// Load test configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadTestConfig {
    /// Target server URL
    pub target_url: String,

    /// Canonical issuer expected in public discovery, independently of HTTP transport.
    #[serde(deserialize_with = "required_discovery_issuer")]
    pub discovery_expected_issuer: Option<String>,

    /// Number of concurrent workers
    pub workers: usize,

    /// Duration of the test
    pub duration: Duration,

    /// Requests per second target
    pub target_rps: f64,

    /// Warm-up duration
    pub warmup_duration: Duration,

    /// Test scenario
    pub scenario: TestScenario,

    /// Enable debug logging
    pub debug: bool,
}

// A nullable value is required: serde's ordinary Option handling accepts absent fields.
fn required_discovery_issuer<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer)
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            target_url: "http://localhost:8080".to_string(),
            discovery_expected_issuer: None,
            workers: 10,
            duration: Duration::from_secs(60),
            target_rps: 100.0,
            warmup_duration: Duration::from_secs(10),
            scenario: TestScenario::Smoke,
            debug: false,
        }
    }
}

/// Test scenarios
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TestScenario {
    /// Smoke endpoints that should succeed on a bare server
    Smoke,

    /// Authorization code flow
    AuthorizationCode,

    /// Token introspection
    Introspection,

    /// Token revocation
    Revocation,

    /// DPoP-bound tokens
    DPoP,

    /// OIDC userinfo
    Userinfo,

    /// OAuth authorization server metadata
    Discovery,

    /// JWKS distribution
    Jwks,

    /// PAR flow
    PAR,

    /// Mixed scenario (all flows)
    Mixed,

    /// Mixed success-path and policy-rejection traffic
    PolicyMixed,

    /// Key rotation stress test
    KeyRotation,
}

impl TestScenario {
    #[must_use]
    pub fn requires_profile(&self) -> bool {
        !matches!(
            self,
            Self::Smoke | Self::Discovery | Self::Jwks | Self::KeyRotation
        )
    }
    #[must_use]
    pub fn requires_oidc(&self) -> bool {
        matches!(self, Self::Userinfo | Self::PolicyMixed)
    }
    #[must_use]
    pub fn requires_dpop(&self) -> bool {
        matches!(self, Self::DPoP | Self::Mixed)
    }
    /// Leg identity is chosen before execution, including failures before HTTP setup.
    #[must_use]
    pub fn leg(&self, iteration: u64) -> (String, bool) {
        let name = match self {
            Self::Smoke => {
                if iteration.is_multiple_of(2) {
                    "health"
                } else {
                    "system-version"
                }
            }
            Self::AuthorizationCode => "auth-code",
            Self::DPoP => "dpop",
            Self::PAR => "par",
            Self::Introspection => "introspection",
            Self::Revocation => "revocation",
            Self::Userinfo => "userinfo",
            Self::Discovery => "discovery",
            Self::Jwks => "jwks",
            Self::KeyRotation => "key-rotation",
            Self::Mixed => ["dpop", "introspection", "revocation", "par"][(iteration % 4) as usize],
            Self::PolicyMixed => [
                "introspection",
                "introspection-missing-client-auth",
                "revocation",
                "revocation-missing-client-auth",
                "userinfo",
                "userinfo-missing-authorization",
            ][(iteration % 6) as usize],
        };
        (
            name.into(),
            matches!(self, Self::PolicyMixed) && iteration % 6 % 2 == 1,
        )
    }
    #[must_use]
    pub fn required_legs(&self) -> Vec<String> {
        let count = match self {
            Self::Smoke => 2,
            Self::Mixed => 4,
            Self::PolicyMixed => 6,
            _ => 1,
        };
        (0..count).map(|i| self.leg(i).0).collect()
    }
}

impl LoadTestConfig {
    /// Validate the same configuration before execution and report acceptance.
    pub fn validate(&self) -> Result<()> {
        crate::url_validation::validate_report_urls(
            &self.target_url,
            self.discovery_expected_issuer.as_deref(),
        )?;
        ensure!(
            !self.duration.is_zero()
                && self.duration.as_secs() <= 86_400
                && self.warmup_duration.as_secs() <= 86_400,
            "run durations must be bounded and main duration positive"
        );
        self.worker_interval()?;
        Ok(())
    }

    /// A representable, positive worker interval; no floating conversion panic.
    pub fn worker_interval(&self) -> Result<Duration> {
        let workers = u32::try_from(self.workers).context("worker count must be representable")?;
        ensure!(
            workers > 0,
            "worker count must be positive and representable"
        );
        ensure!(
            self.target_rps.is_finite() && self.target_rps > 0.0,
            "target invocation rate must be finite and positive"
        );
        let seconds = f64::from(workers) / self.target_rps;
        ensure!(
            seconds.is_finite() && seconds <= 86_400.0,
            "worker pacing interval exceeds bound"
        );
        let interval = Duration::try_from_secs_f64(seconds)
            .context("worker pacing interval is not representable")?;
        ensure!(
            !interval.is_zero(),
            "worker pacing interval must be positive"
        );
        Ok(interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_pacing_rejects_zero_rounding_and_preserves_positive_boundary() -> Result<()> {
        let mut config = LoadTestConfig {
            workers: 1,
            target_rps: 1_000_000_000.0,
            ..LoadTestConfig::default()
        };
        assert_eq!(config.worker_interval()?, Duration::from_nanos(1));
        assert!(config.validate().is_ok());
        for rate in [
            1e20,
            f64::MAX,
            f64::MIN_POSITIVE,
            0.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
        ] {
            config.target_rps = rate;
            assert!(config.worker_interval().is_err(), "admitted rate {rate}");
            assert!(config.validate().is_err());
        }
        config.target_rps = 1.0;
        config.workers = 0;
        assert!(config.validate().is_err());
        config.workers = 1;
        config.duration = Duration::ZERO;
        assert!(config.validate().is_err());
        config.duration = Duration::from_secs(60);
        config.warmup_duration = Duration::from_secs(86_401);
        assert!(config.validate().is_err());
        Ok(())
    }
}
