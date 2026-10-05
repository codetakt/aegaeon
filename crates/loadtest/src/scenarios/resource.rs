//! Introspection, revocation, UserInfo and their rejection legs.
use super::{
    wire::{
        apply_auth, elapsed, nonce_challenge, one_header, response_json, IntrospectionResponse,
        OAuthError, Userinfo,
    },
    ScenarioExecutor,
};
use crate::profile::{scopes, SenderPolicy};
use anyhow::{bail, ensure, Context, Result};
use reqwest::{header::WWW_AUTHENTICATE, StatusCode};
use std::time::Instant;

impl ScenarioExecutor {
    pub async fn introspection_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let token = self.ensure_token(false).await?;
        let profile = self.profile()?.clone();
        let mut params = vec![
            ("token".into(), token.access_token),
            ("token_type_hint".into(), "access_token".into()),
        ];
        let request = apply_auth(
            &profile,
            self.client.post(format!("{}/introspect", self.base_url)),
            &mut params,
        )
        .form(&params);
        let response = self.send("POST", "/introspect", request).await?;
        ensure!(
            response.status == StatusCode::OK,
            "introspection requires HTTP 200"
        );
        let value: IntrospectionResponse =
            response_json(&response.body, "invalid introspection response")?;
        ensure!(
            value.active
                && value.client_id.as_deref() == Some(&profile.supply.client_id)
                && value.sub.as_deref() == Some(&profile.supply.subject)
                && value.iss.as_deref() == Some(&profile.supply.issuer)
                && scopes(
                    value
                        .scope
                        .as_deref()
                        .context("introspection scope missing")?
                )? == scopes(&token.scope)?,
            "introspection does not describe the issued active token"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        ensure!(
            value.exp.is_some_and(|exp| exp > now),
            "introspection has no live token expiry"
        );
        if profile.supply.sender_policy == SenderPolicy::Dpop {
            ensure!(
                value
                    .cnf
                    .as_ref()
                    .and_then(|v| v.get("jkt"))
                    .and_then(|v| v.as_str())
                    == Some(self.generator.dpop_jkt().as_str()),
                "introspection sender key differs from issuing worker"
            );
        }
        if let Some(resource) = token.resource {
            let audience = value
                .aud
                .context("introspection resource audience missing")?;
            ensure!(
                audience.as_str() == Some(&resource)
                    || audience
                        .as_array()
                        .is_some_and(|v| v.len() == 1 && v[0].as_str() == Some(&resource)),
                "introspection audience differs from selected resource"
            );
        }
        Ok((true, elapsed(start)))
    }

    pub async fn revocation_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let token = self.ensure_token(false).await?;
        // The server may revoke the token even if the response cannot be consumed.
        self.cached_access_token = None;
        let profile = self.profile()?.clone();
        let mut params = vec![
            ("token".into(), token.access_token.clone()),
            ("token_type_hint".into(), "access_token".into()),
        ];
        let request = apply_auth(
            &profile,
            self.client.post(format!("{}/revoke", self.base_url)),
            &mut params,
        )
        .form(&params);
        let response = self.send("POST", "/revoke", request).await?;
        ensure!(
            response.status == StatusCode::OK && response.body.is_empty(),
            "revocation must return empty HTTP 200"
        );
        let mut params = vec![("token".into(), token.access_token)];
        let request = apply_auth(
            &profile,
            self.client.post(format!("{}/introspect", self.base_url)),
            &mut params,
        )
        .form(&params);
        let response = self.send("POST", "/introspect", request).await?;
        ensure!(
            response.status == StatusCode::OK,
            "introspection requires HTTP 200"
        );
        let value: IntrospectionResponse =
            response_json(&response.body, "invalid introspection response")?;
        ensure!(!value.active, "revoked token remains active");
        Ok((true, elapsed(start)))
    }

    pub async fn userinfo_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let token = self.ensure_token(true).await?;
        let profile = self.profile()?.clone();
        let subject = token
            .subject
            .context("ID Token must be verified before UserInfo")?;
        let mut nonce = None;
        for attempt in 0..2 {
            let mut request = self.client.get(format!("{}/userinfo", self.base_url));
            let kind = if profile.supply.sender_policy == SenderPolicy::Dpop {
                "DPoP"
            } else {
                "Bearer"
            };
            let mut authorization =
                reqwest::header::HeaderValue::from_str(&format!("{kind} {}", token.access_token))?;
            authorization.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, authorization);
            if profile.supply.sender_policy == SenderPolicy::Dpop {
                request = request.header(
                    "DPoP",
                    self.generator.dpop_proof(
                        "GET",
                        &format!("{}/userinfo", profile.supply.issuer),
                        nonce.as_deref(),
                        Some(&token.access_token),
                    ),
                );
            }
            let response = self.send("GET", "/userinfo", request).await?;
            if let Some(challenge) = nonce_challenge(&response, true)? {
                *self
                    .accounting
                    .nonce_challenges
                    .entry("resource_server".into())
                    .or_default() += 1;
                ensure!(
                    profile.supply.sender_policy == SenderPolicy::Dpop && attempt == 0,
                    "unexpected or repeated RS nonce challenge"
                );
                *self
                    .accounting
                    .nonce_retries
                    .entry("resource_server".into())
                    .or_default() += 1;
                nonce = Some(challenge);
                continue;
            }
            ensure!(
                response.status == StatusCode::OK,
                "UserInfo requires HTTP 200"
            );
            let value: Userinfo = response_json(&response.body, "invalid UserInfo response")?;
            ensure!(
                value.sub == subject,
                "UserInfo subject differs from verified ID Token"
            );
            return Ok((true, elapsed(start)));
        }
        bail!("UserInfo did not complete")
    }

    async fn missing_client_auth(&mut self, endpoint: &str) -> Result<(bool, u64)> {
        let start = Instant::now();
        let request = self
            .client
            .post(format!("{}{endpoint}", self.base_url))
            .form(&[
                ("token", "loadtest-policy-probe"),
                ("token_type_hint", "access_token"),
            ]);
        let response = self.send("POST", endpoint, request).await?;
        ensure!(
            response.status == StatusCode::UNAUTHORIZED,
            "missing client auth must return HTTP 401"
        );
        let auth = one_header(&response.headers, WWW_AUTHENTICATE.as_str())?;
        ensure!(
            auth.starts_with("Basic ") && auth.contains("error=\"invalid_client\""),
            "missing invalid_client authentication challenge"
        );
        if endpoint == "/introspect" {
            ensure!(
                response_json::<OAuthError>(&response.body, "invalid OAuth error response")?.error
                    == "invalid_client",
                "missing invalid_client response"
            );
        }
        Ok((true, elapsed(start)))
    }
    pub async fn introspection_requires_auth_flow(&mut self) -> Result<(bool, u64)> {
        self.missing_client_auth("/introspect").await
    }
    pub async fn revocation_requires_auth_flow(&mut self) -> Result<(bool, u64)> {
        self.missing_client_auth("/revoke").await
    }
    pub async fn userinfo_requires_authorization_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let response = self
            .send(
                "GET",
                "/userinfo",
                self.client.get(format!("{}/userinfo", self.base_url)),
            )
            .await?;
        ensure!(
            response.status == StatusCode::UNAUTHORIZED,
            "missing UserInfo authorization must return HTTP 401"
        );
        Ok((true, elapsed(start)))
    }
}
