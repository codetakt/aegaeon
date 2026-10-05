//! Issued-token validation, OIDC verification and per-worker cache lifetimes.
use super::{
    authorization::authorization_code,
    wire::{apply_auth, elapsed, nonce_challenge, TokenResponse},
    ScenarioExecutor,
};
use crate::{
    oidc::verify_id_token,
    profile::{scopes, sha256, ClientProfile, SenderPolicy},
};
use anyhow::{ensure, Context, Result};
use reqwest::StatusCode;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(super) struct CachedToken {
    pub(super) access_token: String,
    pub(super) scope: String,
    pub(super) resource: Option<String>,
    pub(super) subject: Option<String>,
    pub(super) expires: Instant,
}

impl ScenarioExecutor {
    async fn exchange_token(
        &mut self,
        profile: &ClientProfile,
        params: &[(String, String)],
    ) -> Result<TokenResponse> {
        let mut nonce = None;
        let mut token = None;
        for attempt in 0..2 {
            let mut request = self.client.post(format!("{}/token", self.base_url));
            let mut wire_params = params.to_vec();
            request = apply_auth(profile, request, &mut wire_params).form(&wire_params);
            if profile.supply.sender_policy == SenderPolicy::Dpop {
                let proof = self.generator.dpop_proof(
                    "POST",
                    &format!("{}/token", profile.supply.issuer),
                    nonce.as_deref(),
                    None,
                );
                request = request.header("DPoP", proof);
            }
            let response = self.send("POST", "/token", request).await?;
            if let Some(challenge) = nonce_challenge(&response, false)? {
                *self
                    .accounting
                    .nonce_challenges
                    .entry("authorization_server".into())
                    .or_default() += 1;
                ensure!(
                    profile.supply.sender_policy == SenderPolicy::Dpop && attempt == 0,
                    "unexpected or repeated AS nonce challenge"
                );
                *self
                    .accounting
                    .nonce_retries
                    .entry("authorization_server".into())
                    .or_default() += 1;
                nonce = Some(challenge);
                continue;
            }
            ensure!(
                response.status == StatusCode::OK,
                "token exchange requires HTTP 200"
            );
            token = Some(
                serde_json::from_slice::<TokenResponse>(&response.body)
                    .context("invalid token response")?,
            );
            break;
        }
        let token = token.context("token exchange did not complete")?;
        Ok(token)
    }

    pub(super) fn validate_access_token(
        profile: &ClientProfile,
        token: &TokenResponse,
        authorized_scope: &str,
    ) -> Result<(String, u64)> {
        ensure!(!token.access_token.trim().is_empty(), "empty access token");
        ensure!(
            token.token_type
                == if profile.supply.sender_policy == SenderPolicy::Dpop {
                    "DPoP"
                } else {
                    "Bearer"
                },
            "access token type differs from sender policy"
        );
        let ttl = token
            .expires_in
            .filter(|v| *v > 0)
            .context("missing or nonpositive token expiry")?;
        let effective: String = authorized_scope
            .split(' ')
            .filter(|v| *v != "offline_access")
            .collect::<Vec<_>>()
            .join(" ");
        ensure!(
            scopes(
                token
                    .scope
                    .as_deref()
                    .context("token response must identify effective scope")?
            )? == scopes(&effective)?,
            "access token scope differs from authorized scope"
        );
        ensure!(
            token.refresh_token.is_none(),
            "prompt=none does not establish offline consent"
        );
        Ok((effective, ttl))
    }

    pub(super) async fn issue_token(&mut self, oidc: bool, force_par: bool) -> Result<CachedToken> {
        let profile = self.profile()?.clone();
        profile.supply.validate(&self.base_url, oidc, false)?;
        let scope = if oidc {
            profile
                .supply
                .oidc_scope
                .clone()
                .context("missing OIDC scope")?
        } else {
            profile.supply.scope.clone()
        };
        let resource = if oidc {
            Some(format!("{}/userinfo", profile.supply.issuer))
        } else {
            profile.supply.resource.clone()
        };
        let tx = self.transaction(scope, resource)?;
        let params = self.authorization_params(&profile, &tx, force_par).await?;
        let request = self
            .client
            .get(format!("{}/authorize", self.base_url))
            .query(&params)
            .header(reqwest::header::COOKIE, profile.session_cookie.clone());
        let response = self.send("GET", "/authorize", request).await?;
        let code = authorization_code(
            response.status,
            &response.headers,
            &profile.supply.redirect_uri,
            &tx.state,
            &profile.supply.issuer,
        )?;
        let mut params = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.clone()),
            ("client_id".into(), profile.supply.client_id.clone()),
            ("redirect_uri".into(), profile.supply.redirect_uri.clone()),
            ("code_verifier".into(), tx.pkce.verifier),
        ];
        if let Some(value) = &tx.resource {
            params.push(("resource".into(), value.clone()));
        }
        let exchange_started = Instant::now();
        let token = self.exchange_token(&profile, &params).await?;
        let (effective, ttl) = Self::validate_access_token(&profile, &token, &tx.scope)?;
        let expires = exchange_started
            .checked_add(Duration::from_secs(ttl))
            .context("token expiry exceeds clock range")?;
        let subject = if let Some(expected_nonce) = tx.nonce {
            let id = token
                .id_token
                .as_deref()
                .context("missing ID Token for openid transaction")?;
            let response = self
                .send(
                    "GET",
                    "/.well-known/jwks.json",
                    self.client
                        .get(format!("{}/.well-known/jwks.json", self.base_url)),
                )
                .await?;
            self.jwks_sha256 = Some(sha256(&response.body));
            ensure!(response.status == StatusCode::OK, "JWKS requires HTTP 200");
            let (subject, _) = verify_id_token(
                id,
                &response.body,
                &profile.supply,
                &expected_nonce,
                &token.access_token,
                &code,
            )?;
            Some(subject)
        } else {
            ensure!(
                token.id_token.is_none(),
                "unexpected ID Token without openid transaction"
            );
            None
        };
        ensure!(expires > Instant::now(), "token expired before delivery");
        Ok(CachedToken {
            access_token: token.access_token,
            scope: effective,
            resource: tx.resource,
            subject,
            expires,
        })
    }

    pub(super) async fn ensure_token(&mut self, oidc: bool) -> Result<CachedToken> {
        let cached = if oidc {
            &self.cached_userinfo_access_token
        } else {
            &self.cached_access_token
        };
        if let Some(token) = cached.as_ref().filter(|t| t.expires > Instant::now()) {
            return Ok(token.clone());
        }
        let token = self.issue_token(oidc, false).await?;
        if oidc {
            self.cached_userinfo_access_token = Some(token.clone());
        } else {
            self.cached_access_token = Some(token.clone());
        }
        Ok(token)
    }

    pub async fn authorization_code_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let token = self.issue_token(false, false).await?;
        self.cached_access_token = Some(token);
        Ok((true, elapsed(start)))
    }
    pub async fn dpop_flow(&mut self) -> Result<(bool, u64)> {
        ensure!(
            self.profile()?.supply.sender_policy == SenderPolicy::Dpop,
            "DPoP scenario requires DPoP profile"
        );
        self.authorization_code_flow().await
    }
    pub async fn par_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let token = self.issue_token(false, true).await?;
        self.cached_access_token = Some(token);
        Ok((true, elapsed(start)))
    }
}
