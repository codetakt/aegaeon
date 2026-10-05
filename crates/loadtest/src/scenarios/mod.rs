//! Public scenario executor and mixed-leg orchestration.
mod authorization;
mod public;
mod resource;
#[cfg(test)]
mod tests;
mod token;
mod wire;

use crate::{
    accounting::HttpAccounting, generator::TestDataGenerator, profile::ClientProfile, TestScenario,
};
use anyhow::{bail, ensure, Context, Result};
use reqwest::Client;
use std::time::Duration;
use token::CachedToken;
pub use wire::{IntrospectionResponse, TokenResponse};

pub struct ScenarioExecutor {
    client: Client,
    base_url: String,
    discovery_expected_issuer: String,
    generator: TestDataGenerator,
    profile: Option<ClientProfile>,
    cached_access_token: Option<CachedToken>,
    cached_userinfo_access_token: Option<CachedToken>,
    accounting: HttpAccounting,
    pub jwks_sha256: Option<String>,
}

impl ScenarioExecutor {
    pub fn new(base_url: String) -> Result<Self> {
        Self::for_scenario(base_url, &TestScenario::Smoke)
    }

    pub fn for_scenario(base_url: String, scenario: &TestScenario) -> Result<Self> {
        Self::for_scenario_with_discovery_issuer(base_url, scenario, None)
    }

    pub fn for_scenario_with_discovery_issuer(
        base_url: String,
        scenario: &TestScenario,
        expected_issuer: Option<&str>,
    ) -> Result<Self> {
        if matches!(scenario, TestScenario::KeyRotation) {
            bail!("key-rotation is unsupported: HUMAN management/NEXT replenishment/restart supervision remains required");
        }
        let profile = if scenario.requires_profile() {
            Some(ClientProfile::from_env(
                &base_url,
                scenario.requires_oidc(),
                scenario.requires_dpop(),
            )?)
        } else {
            None
        };
        let mut executor = Self::with_profile(base_url, profile)?;
        if let Some(issuer) = expected_issuer {
            let url = crate::profile::issuer_url(issuer)?;
            ensure!(
                url.as_str().trim_end_matches('/') == issuer,
                "discovery issuer must be a canonical HTTPS URL"
            );
            issuer.clone_into(&mut executor.discovery_expected_issuer);
        }
        Ok(executor)
    }

    pub fn with_profile(mut base_url: String, profile: Option<ClientProfile>) -> Result<Self> {
        crate::url_validation::validate_report_urls(&base_url, None)?;
        if let Some(selected) = &profile {
            selected.supply.validate(&base_url, false, false)?;
        }
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30));
        if let Some(path) = std::env::var_os("AEG_LOADTEST_CA_CERT") {
            let ca = std::fs::read(path).context("cannot read fixture CA certificate")?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&ca).context("invalid fixture CA certificate")?,
            );
        }
        base_url.truncate(base_url.trim_end_matches('/').len());
        Ok(Self {
            client: builder.build()?,
            discovery_expected_issuer: base_url.clone(),
            base_url,
            profile,
            generator: TestDataGenerator::new(),
            cached_access_token: None,
            cached_userinfo_access_token: None,
            accounting: HttpAccounting::default(),
            jwks_sha256: None,
        })
    }

    fn profile(&self) -> Result<&ClientProfile> {
        self.profile
            .as_ref()
            .context("selected flow requires an activated profile")
    }

    pub fn supplier_identity(&self) -> Option<(String, String)> {
        self.profile.as_ref().map(|p| {
            (
                p.profile_sha256.clone(),
                p.session_provenance_sha256.clone(),
            )
        })
    }

    #[must_use]
    pub fn fork_worker(&self) -> Self {
        Self {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            discovery_expected_issuer: self.discovery_expected_issuer.clone(),
            generator: TestDataGenerator::new(),
            profile: self.profile.clone(),
            cached_access_token: None,
            cached_userinfo_access_token: None,
            accounting: HttpAccounting::default(),
            jwks_sha256: None,
        }
    }

    pub fn take_accounting(&mut self) -> HttpAccounting {
        std::mem::take(&mut self.accounting)
    }

    pub async fn mixed_flow(&mut self, iteration: u64) -> Result<(TestScenario, bool, u64)> {
        let (scenario, outcome) = match iteration % 4 {
            0 => (TestScenario::DPoP, self.dpop_flow().await),
            1 => (TestScenario::Introspection, self.introspection_flow().await),
            2 => (TestScenario::Revocation, self.revocation_flow().await),
            _ => (TestScenario::PAR, self.par_flow().await),
        };
        let (success, latency) = outcome?;
        Ok((scenario, success, latency))
    }
    pub async fn policy_mixed_flow(&mut self, iteration: u64) -> Result<(TestScenario, bool, u64)> {
        let (scenario, outcome) = match iteration % 6 {
            0 => (TestScenario::Introspection, self.introspection_flow().await),
            1 => (
                TestScenario::Introspection,
                self.introspection_requires_auth_flow().await,
            ),
            2 => (TestScenario::Revocation, self.revocation_flow().await),
            3 => (
                TestScenario::Revocation,
                self.revocation_requires_auth_flow().await,
            ),
            4 => (TestScenario::Userinfo, self.userinfo_flow().await),
            _ => (
                TestScenario::Userinfo,
                self.userinfo_requires_authorization_flow().await,
            ),
        };
        let (success, latency) = outcome?;
        Ok((scenario, success, latency))
    }
}
