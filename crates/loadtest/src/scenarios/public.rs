//! Bare-server smoke, discovery and JWKS scenarios.
use super::{
    wire::{elapsed, response_json},
    ScenarioExecutor,
};
use crate::{profile::sha256, TestScenario};
use anyhow::{bail, ensure, Result};
use reqwest::StatusCode;
use std::time::Instant;

impl ScenarioExecutor {
    pub async fn smoke_flow(&mut self, iteration: u64) -> Result<(TestScenario, bool, u64)> {
        let start = Instant::now();
        let endpoint = if iteration.is_multiple_of(2) {
            "/health"
        } else {
            "/api/v1/system/version"
        };
        let response = self
            .send(
                "GET",
                endpoint,
                self.client.get(format!("{}{endpoint}", self.base_url)),
            )
            .await?;
        ensure!(
            response.status == StatusCode::OK,
            "public smoke endpoint requires HTTP 200"
        );
        Ok((TestScenario::Smoke, true, elapsed(start)))
    }
    pub async fn discovery_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let endpoint = "/.well-known/oauth-authorization-server";
        let response = self
            .send(
                "GET",
                endpoint,
                self.client.get(format!("{}{endpoint}", self.base_url)),
            )
            .await?;
        ensure!(
            response.status == StatusCode::OK,
            "Discovery requires HTTP 200"
        );
        let metadata: serde_json::Value =
            response_json(&response.body, "invalid discovery response")?;
        ensure!(
            metadata["issuer"].as_str() == Some(&self.discovery_expected_issuer)
                && metadata["token_endpoint"].as_str()
                    == Some(format!("{}/token", self.discovery_expected_issuer).as_str())
                && metadata["jwks_uri"].as_str()
                    == Some(format!("{}/jwks", self.discovery_expected_issuer).as_str()),
            "Discovery endpoint/issuer mismatch"
        );
        Ok((true, elapsed(start)))
    }
    pub async fn jwks_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let endpoint = "/.well-known/jwks.json";
        let response = self
            .send(
                "GET",
                endpoint,
                self.client.get(format!("{}{endpoint}", self.base_url)),
            )
            .await?;
        self.jwks_sha256 = Some(sha256(&response.body));
        ensure!(response.status == StatusCode::OK, "JWKS requires HTTP 200");
        let _: jsonwebtoken::jwk::JwkSet = response_json(&response.body, "invalid JWKS response")?;
        Ok((true, elapsed(start)))
    }
    pub fn key_rotation_flow(&mut self) -> Result<(bool, u64)> {
        bail!(
            "key-rotation is unsupported: HUMAN/NEXT/restart supervisor contract remains required"
        )
    }
}
