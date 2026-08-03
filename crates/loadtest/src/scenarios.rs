use crate::generator::TestDataGenerator;
use crate::TestScenario;
use anyhow::{Context, Result};
use reqwest::{header::HeaderMap, Client, RequestBuilder, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Deserialize)]
struct AuthorizationSuccess {
    code: String,
    #[allow(dead_code)]
    state: Option<String>,
}

#[derive(Deserialize)]
struct ParSuccess {
    request_uri: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

enum TokenExchangeOutcome {
    Success(TokenResponse),
    DpopNonceChallenge(String),
    Failure,
}

#[must_use]
fn has_invalid_client_authenticate(headers: &HeaderMap) -> bool {
    headers
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("invalid_client"))
}

#[must_use]
fn is_unauthenticated_introspection_rejection(
    status: StatusCode,
    headers: &HeaderMap,
    error: &OAuthErrorResponse,
) -> bool {
    status == StatusCode::UNAUTHORIZED
        && has_invalid_client_authenticate(headers)
        && error.error.as_deref() == Some("invalid_client")
}

#[must_use]
fn is_unauthenticated_revocation_rejection(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::UNAUTHORIZED && has_invalid_client_authenticate(headers)
}

#[must_use]
fn is_userinfo_missing_authorization(status: StatusCode) -> bool {
    status == StatusCode::UNAUTHORIZED
}

#[must_use]
fn elapsed_millis_u64(start: &Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug)]
struct ClientProfile {
    id: String,
    secret: Option<String>,
    redirect_uri: String,
    scope: String,
}

impl ClientProfile {
    fn from_env() -> Self {
        let id =
            std::env::var("AEG_LOADTEST_CLIENT_ID").unwrap_or_else(|_| "test-client".to_string());
        let secret = match std::env::var("AEG_LOADTEST_CLIENT_SECRET") {
            Ok(val) if !val.is_empty() => Some(val),
            Ok(_) => None,
            Err(_) => Some("test-secret".to_string()),
        };
        let redirect_uri = std::env::var("AEG_LOADTEST_REDIRECT_URI")
            .unwrap_or_else(|_| "https://example.com/callback".to_string());
        let scope =
            std::env::var("AEG_LOADTEST_SCOPE").unwrap_or_else(|_| "read write".to_string());

        Self {
            id,
            secret,
            redirect_uri,
            scope,
        }
    }
}

/// OAuth token response
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// Introspection response
#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UserinfoResponse {
    sub: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationServerMetadataResponse {
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Test scenario executor
pub struct ScenarioExecutor {
    client: Client,
    base_url: String,
    generator: TestDataGenerator,
    client_profile: ClientProfile,
    forwarded_header: String,
    cached_access_token: Option<String>,
    cached_userinfo_access_token: Option<String>,
}

impl ScenarioExecutor {
    /// Construct a scenario executor for a single worker.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying HTTP client cannot be initialized.
    pub fn new(base_url: String) -> Result<Self> {
        let forwarded_header = Url::parse(&base_url).ok().map_or_else(
            || "proto=https;host=localhost".to_string(),
            |url| {
                let host = url.host_str().unwrap_or("localhost");
                let port = url
                    .port()
                    .map_or_else(|| host.to_string(), |port| format!("{host}:{port}"));
                format!("proto=https;host={port}")
            },
        );

        let client_profile = ClientProfile::from_env();
        tracing::debug!(profile = ?client_profile, "initialized loadtest client profile");

        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("failed to initialize loadtest HTTP client")?,
            base_url,
            generator: TestDataGenerator::new(),
            client_profile,
            forwarded_header,
            cached_access_token: None,
            cached_userinfo_access_token: None,
        })
    }

    fn authorization_code_params_for_scope(
        &mut self,
        scope: &str,
    ) -> (crate::generator::PkcePair, Vec<(String, String)>) {
        let profile = &self.client_profile;
        let state = self.generator.state();
        let pkce = self.generator.pkce_pair();

        let mut params = vec![
            ("response_type".to_string(), "code".to_string()),
            ("client_id".to_string(), profile.id.clone()),
            ("redirect_uri".to_string(), profile.redirect_uri.clone()),
            ("scope".to_string(), scope.to_string()),
            ("code_challenge".to_string(), pkce.challenge.clone()),
            ("code_challenge_method".to_string(), "S256".to_string()),
        ];
        if !state.is_empty() {
            params.push(("state".to_string(), state));
        }
        if scope.split_whitespace().any(|value| value == "openid") {
            params.push(("nonce".to_string(), self.generator.nonce()));
        }

        (pkce, params)
    }

    fn authorization_code_params(&mut self) -> (crate::generator::PkcePair, Vec<(String, String)>) {
        let scope = self.client_profile.scope.clone();
        self.authorization_code_params_for_scope(scope.as_str())
    }

    fn maybe_add_client_secret_post(&self, params: &mut Vec<(String, String)>) {
        if self.client_profile.secret.is_some() {
            return;
        }

        if let Ok(secret) = std::env::var("AEG_LOADTEST_CLIENT_SECRET_POST") {
            if !secret.trim().is_empty() {
                params.push(("client_secret".to_string(), secret));
            }
        }
    }

    fn apply_client_auth(&self, request: RequestBuilder) -> RequestBuilder {
        if self.client_profile.secret.is_some() {
            request.basic_auth(
                self.client_profile.id.clone(),
                self.client_profile.secret.clone(),
            )
        } else {
            request
        }
    }

    fn proof_origin(&self) -> String {
        std::env::var("AEG_LOADTEST_PROOF_ORIGIN")
            .or_else(|_| std::env::var("AEG_LOADTEST_PUBLIC_ORIGIN"))
            .unwrap_or_else(|_| self.base_url.trim_end_matches('/').to_string())
    }

    fn token_endpoint(&self) -> String {
        format!("{}/token", self.base_url.trim_end_matches('/'))
    }

    fn userinfo_endpoint(&self) -> String {
        format!("{}/userinfo", self.base_url.trim_end_matches('/'))
    }

    fn discovery_endpoint(&self) -> String {
        format!(
            "{}/.well-known/oauth-authorization-server",
            self.base_url.trim_end_matches('/')
        )
    }

    fn jwks_endpoint(&self) -> String {
        format!(
            "{}/.well-known/jwks.json",
            self.base_url.trim_end_matches('/')
        )
    }

    fn token_proof_htu(&self) -> String {
        format!("{}/token", self.proof_origin().trim_end_matches('/'))
    }

    fn userinfo_proof_htu(&self) -> String {
        format!("{}/userinfo", self.proof_origin().trim_end_matches('/'))
    }

    fn oidc_scope() -> String {
        std::env::var("AEG_LOADTEST_OIDC_SCOPE").unwrap_or_else(|_| "openid profile".to_string())
    }

    async fn request_authorization_code(
        &self,
        auth_params: &[(String, String)],
        flow_name: &'static str,
    ) -> Option<AuthorizationSuccess> {
        let auth_response = match self
            .client
            .get(format!("{}/authorize", self.base_url))
            .query(auth_params)
            .header("Forwarded", &self.forwarded_header)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(flow = flow_name, error = %err, "authorization request failed to send");
                return None;
            }
        };

        let auth_status = auth_response.status();
        let auth_body_text = auth_response.text().await.unwrap_or_default();
        if !auth_status.is_success() {
            tracing::debug!(
                flow = flow_name,
                status = %auth_status,
                body = %auth_body_text,
                "authorization request failed"
            );
            return None;
        }

        match serde_json::from_str(&auth_body_text) {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::debug!(
                    flow = flow_name,
                    error = %err,
                    body = %auth_body_text,
                    "failed to parse authorization response"
                );
                None
            }
        }
    }

    async fn submit_authorization_code_exchange(
        &self,
        token_params: &[(String, String)],
        dpop_proof: Option<&str>,
        flow_name: &'static str,
    ) -> TokenExchangeOutcome {
        let mut token_request = self
            .client
            .post(self.token_endpoint())
            .header("Forwarded", &self.forwarded_header)
            .form(token_params);
        if let Some(proof) = dpop_proof {
            token_request = token_request.header("DPoP", proof);
        }
        token_request = self.apply_client_auth(token_request);

        let token_response = match token_request.send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(flow = flow_name, error = %err, "token request failed to send");
                return TokenExchangeOutcome::Failure;
            }
        };

        let token_status = token_response.status();
        let dpop_nonce = token_response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let token_body_text = token_response.text().await.unwrap_or_default();
        if !token_status.is_success() {
            let error_response =
                serde_json::from_str::<OAuthErrorResponse>(&token_body_text).unwrap_or_default();
            if token_status == StatusCode::BAD_REQUEST
                && error_response.error.as_deref() == Some("use_dpop_nonce")
            {
                if let Some(nonce) = dpop_nonce {
                    tracing::debug!(
                        flow = flow_name,
                        nonce = %nonce,
                        "token request challenged with DPoP nonce"
                    );
                    return TokenExchangeOutcome::DpopNonceChallenge(nonce);
                }
            }

            tracing::debug!(
                flow = flow_name,
                status = %token_status,
                error = ?error_response.error,
                error_description = ?error_response.error_description,
                dpop_nonce = ?dpop_nonce,
                body = %token_body_text,
                "token request failed"
            );
            return TokenExchangeOutcome::Failure;
        }

        let token = match serde_json::from_str::<TokenResponse>(&token_body_text) {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(
                    flow = flow_name,
                    error = %err,
                    body = %token_body_text,
                    "failed to parse token response"
                );
                return TokenExchangeOutcome::Failure;
            }
        };

        if token.access_token.trim().is_empty() {
            return TokenExchangeOutcome::Failure;
        }

        TokenExchangeOutcome::Success(token)
    }

    async fn exchange_authorization_code(
        &mut self,
        code: String,
        verifier: String,
        dpop_htu: Option<&str>,
        flow_name: &'static str,
    ) -> Option<TokenResponse> {
        let profile = &self.client_profile;
        let mut token_params = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code),
            ("client_id".to_string(), profile.id.clone()),
            ("redirect_uri".to_string(), profile.redirect_uri.clone()),
            ("code_verifier".to_string(), verifier),
        ];
        self.maybe_add_client_secret_post(&mut token_params);
        let initial_proof = dpop_htu.map(|htu| self.generator.dpop_proof("POST", htu, None, None));
        match self
            .submit_authorization_code_exchange(&token_params, initial_proof.as_deref(), flow_name)
            .await
        {
            TokenExchangeOutcome::Success(token) => Some(token),
            TokenExchangeOutcome::Failure => None,
            TokenExchangeOutcome::DpopNonceChallenge(nonce) => {
                let Some(htu) = dpop_htu else {
                    tracing::debug!(
                        flow = flow_name,
                        "received DPoP nonce challenge without DPoP context"
                    );
                    return None;
                };
                let retry_proof = self.generator.dpop_proof("POST", htu, Some(&nonce), None);
                match self
                    .submit_authorization_code_exchange(
                        &token_params,
                        Some(&retry_proof),
                        flow_name,
                    )
                    .await
                {
                    TokenExchangeOutcome::Success(token) => Some(token),
                    TokenExchangeOutcome::DpopNonceChallenge(_) => {
                        tracing::debug!(
                            flow = flow_name,
                            "token request received repeated DPoP nonce challenge"
                        );
                        None
                    }
                    TokenExchangeOutcome::Failure => None,
                }
            }
        }
    }

    async fn request_par_uri(&self, mut par_params: Vec<(String, String)>) -> Option<ParSuccess> {
        let mut par_request = self
            .client
            .post(format!("{}/par", self.base_url))
            .header("Forwarded", &self.forwarded_header);
        self.maybe_add_client_secret_post(&mut par_params);
        par_request = self.apply_client_auth(par_request);

        let par_response = match par_request.form(&par_params).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "par request failed to send");
                return None;
            }
        };

        let par_status = par_response.status();
        let par_body_text = par_response.text().await.unwrap_or_default();
        if !par_status.is_success() {
            tracing::debug!(status = %par_status, body = %par_body_text, "par request failed");
            return None;
        }

        match serde_json::from_str(&par_body_text) {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::debug!(error = %err, body = %par_body_text, "failed to parse par response");
                None
            }
        }
    }

    async fn issue_token_with_scope(
        &mut self,
        scope: &str,
        sender_constrained: bool,
        flow_name: &'static str,
    ) -> Result<TokenResponse> {
        let (pkce, auth_params) = self.authorization_code_params_for_scope(scope);
        let auth_body = self
            .request_authorization_code(&auth_params, flow_name)
            .await
            .context("authorization request failed")?;
        let dpop_htu = sender_constrained.then(|| self.token_proof_htu());
        self.exchange_authorization_code(
            auth_body.code,
            pkce.verifier,
            dpop_htu.as_deref(),
            flow_name,
        )
        .await
        .context("token exchange failed")
    }

    async fn issue_token_via_authorization_code(&mut self) -> Result<TokenResponse> {
        let scope = self.client_profile.scope.clone();
        self.issue_token_with_scope(scope.as_str(), false, "authorization_code")
            .await
    }

    async fn issue_sender_constrained_token(&mut self) -> Result<TokenResponse> {
        let scope = self.client_profile.scope.clone();
        self.issue_token_with_scope(scope.as_str(), true, "sender_constrained_token")
            .await
    }

    async fn ensure_access_token(&mut self) -> Result<String> {
        if let Some(token) = self.cached_access_token.clone() {
            return Ok(token);
        }
        let token = self.issue_sender_constrained_token().await?;
        self.cached_access_token = Some(token.access_token.clone());
        Ok(token.access_token)
    }

    async fn ensure_userinfo_access_token(&mut self) -> Result<String> {
        if let Some(token) = self.cached_userinfo_access_token.clone() {
            return Ok(token);
        }
        let scope = Self::oidc_scope();
        let token = self
            .issue_token_with_scope(scope.as_str(), true, "userinfo_authorization_code")
            .await?;
        self.cached_userinfo_access_token = Some(token.access_token.clone());
        Ok(token.access_token)
    }

    /// Execute a smoke check against public endpoints that should succeed on a bare server.
    ///
    /// # Errors
    ///
    /// Returns an error when local request construction fails.
    pub async fn smoke_flow(&self, iteration: u64) -> Result<(TestScenario, bool, u64)> {
        if iteration.is_multiple_of(2) {
            let (success, latency) = self.health_flow().await?;
            Ok((TestScenario::Smoke, success, latency))
        } else {
            let (success, latency) = self.system_version_flow().await?;
            Ok((TestScenario::Smoke, success, latency))
        }
    }

    async fn health_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let response = match self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "health request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        Ok((response.status().is_success(), elapsed_millis_u64(&start)))
    }

    async fn system_version_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let response = match self
            .client
            .get(format!("{}/api/v1/system/version", self.base_url))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "system version request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        Ok((response.status().is_success(), elapsed_millis_u64(&start)))
    }

    /// Execute an OAuth authorization server metadata request.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn discovery_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let response = match self.client.get(self.discovery_endpoint()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "discovery request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            tracing::debug!(status = %status, body = %body_text, "discovery request failed");
            return Ok((false, elapsed_millis_u64(&start)));
        }

        let metadata = match serde_json::from_str::<AuthorizationServerMetadataResponse>(&body_text)
        {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    body = %body_text,
                    "failed to parse discovery response"
                );
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let success = !metadata.issuer.trim().is_empty()
            && !metadata.token_endpoint.trim().is_empty()
            && !metadata.jwks_uri.trim().is_empty();
        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute a JWKS distribution request.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn jwks_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let response = match self.client.get(self.jwks_endpoint()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "jwks request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            tracing::debug!(status = %status, body = %body_text, "jwks request failed");
            return Ok((false, elapsed_millis_u64(&start)));
        }

        let jwks = match serde_json::from_str::<serde_json::Value>(&body_text) {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(error = %err, body = %body_text, "failed to parse jwks response");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let success = jwks
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .is_some();
        Ok((success, elapsed_millis_u64(&start)))
    }

    async fn submit_userinfo_request(
        &mut self,
        access_token: &str,
        nonce: Option<&str>,
        flow_name: &'static str,
    ) -> TokenExchangeOutcome {
        let userinfo_endpoint = self.userinfo_endpoint();
        let userinfo_proof_htu = self.userinfo_proof_htu();
        let proof =
            self.generator
                .dpop_proof("GET", &userinfo_proof_htu, nonce, Some(access_token));

        let response = match self
            .client
            .get(&userinfo_endpoint)
            .header("Forwarded", &self.forwarded_header)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(flow = flow_name, error = %err, "userinfo request failed to send");
                return TokenExchangeOutcome::Failure;
            }
        };

        let status = response.status();
        let dpop_nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body_text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let error_response =
                serde_json::from_str::<OAuthErrorResponse>(&body_text).unwrap_or_default();
            if status == StatusCode::BAD_REQUEST
                && error_response.error.as_deref() == Some("use_dpop_nonce")
            {
                if let Some(nonce_value) = dpop_nonce {
                    tracing::debug!(
                        flow = flow_name,
                        nonce = %nonce_value,
                        "userinfo request challenged with DPoP nonce"
                    );
                    return TokenExchangeOutcome::DpopNonceChallenge(nonce_value);
                }
            }

            tracing::debug!(
                flow = flow_name,
                status = %status,
                error = ?error_response.error,
                error_description = ?error_response.error_description,
                dpop_nonce = ?dpop_nonce,
                body = %body_text,
                "userinfo request failed"
            );
            return TokenExchangeOutcome::Failure;
        }

        let userinfo = match serde_json::from_str::<UserinfoResponse>(&body_text) {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(
                    flow = flow_name,
                    error = %err,
                    body = %body_text,
                    "failed to parse userinfo response"
                );
                return TokenExchangeOutcome::Failure;
            }
        };

        if userinfo.sub.trim().is_empty() {
            return TokenExchangeOutcome::Failure;
        }

        TokenExchangeOutcome::Success(TokenResponse {
            access_token: access_token.to_string(),
            token_type: "DPoP".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        })
    }

    /// Execute the authorization code flow against the target server.
    ///
    /// # Errors
    ///
    /// Returns an error when response parsing or client-side request construction fails.
    pub async fn authorization_code_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let (success, access_token) = match self.issue_token_via_authorization_code().await {
            Ok(token) => (true, Some(token.access_token)),
            Err(err) => {
                tracing::debug!(error = %err, "authorization_code_flow failed");
                (false, None)
            }
        };

        if let Some(token) = access_token {
            self.cached_access_token = Some(token);
        }

        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute an introspection request.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn introspection_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();

        let token = match self.ensure_access_token().await {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(error = %err, "introspection_flow failed to obtain token");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let profile = &self.client_profile;
        let mut params = vec![
            ("token".to_string(), token),
            ("token_type_hint".to_string(), "access_token".to_string()),
        ];

        let mut request = self
            .client
            .post(format!("{}/introspect", self.base_url))
            .header("Forwarded", &self.forwarded_header);

        if profile.secret.is_some() {
            request = request.basic_auth(profile.id.clone(), profile.secret.clone());
        } else if let Ok(secret) = std::env::var("AEG_LOADTEST_CLIENT_SECRET_POST") {
            if !secret.trim().is_empty() {
                params.push(("client_id".to_string(), profile.id.clone()));
                params.push(("client_secret".to_string(), secret));
            }
        }

        let response = match request.form(&params).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "introspection request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            tracing::debug!(status = %status, body = %body_text, "introspection request failed");
            return Ok((false, elapsed_millis_u64(&start)));
        }

        let introspection: IntrospectionResponse = match serde_json::from_str(&body_text) {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(error = %err, body = %body_text, "failed to parse introspection response");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        Ok((introspection.active, elapsed_millis_u64(&start)))
    }

    /// Execute an introspection request that should be rejected for missing client authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn introspection_requires_auth_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let params = vec![
            ("token".to_string(), "loadtest-policy-probe".to_string()),
            ("token_type_hint".to_string(), "access_token".to_string()),
        ];

        let response = match self
            .client
            .post(format!("{}/introspect", self.base_url))
            .header("Forwarded", &self.forwarded_header)
            .form(&params)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "unauthenticated introspection request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let status = response.status();
        let headers = response.headers().clone();
        let body_text = response.text().await.unwrap_or_default();
        let error_response =
            serde_json::from_str::<OAuthErrorResponse>(&body_text).unwrap_or_default();
        let success = is_unauthenticated_introspection_rejection(status, &headers, &error_response);
        if !success {
            tracing::debug!(
                status = %status,
                headers = ?headers,
                error = ?error_response.error,
                error_description = ?error_response.error_description,
                body = %body_text,
                "unauthenticated introspection request did not receive the expected rejection"
            );
        }

        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute a revocation request.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn revocation_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();

        let token = match self.ensure_access_token().await {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(error = %err, "revocation_flow failed to obtain token");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let profile = &self.client_profile;
        let mut params = vec![
            ("token".to_string(), token),
            ("token_type_hint".to_string(), "access_token".to_string()),
        ];

        let mut request = self
            .client
            .post(format!("{}/revoke", self.base_url))
            .header("Forwarded", &self.forwarded_header);

        if profile.secret.is_some() {
            request = request.basic_auth(profile.id.clone(), profile.secret.clone());
        } else if let Ok(secret) = std::env::var("AEG_LOADTEST_CLIENT_SECRET_POST") {
            if !secret.trim().is_empty() {
                params.push(("client_id".to_string(), profile.id.clone()));
                params.push(("client_secret".to_string(), secret));
            }
        }

        let response = match request.form(&params).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "revocation request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let success = response.status().is_success();
        if success {
            self.cached_access_token = None;
        }

        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute a revocation request that should be rejected for missing client authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn revocation_requires_auth_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let params = vec![
            ("token".to_string(), "loadtest-policy-probe".to_string()),
            ("token_type_hint".to_string(), "access_token".to_string()),
        ];

        let response = match self
            .client
            .post(format!("{}/revoke", self.base_url))
            .header("Forwarded", &self.forwarded_header)
            .form(&params)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "unauthenticated revocation request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let status = response.status();
        let headers = response.headers().clone();
        let body_text = response.text().await.unwrap_or_default();
        let success = is_unauthenticated_revocation_rejection(status, &headers);
        if !success {
            tracing::debug!(
                status = %status,
                headers = ?headers,
                body = %body_text,
                "unauthenticated revocation request did not receive the expected rejection"
            );
        }

        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute a DPoP-bound token request.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn dpop_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let Some(token) = self
            .issue_sender_constrained_token()
            .await
            .map_err(|err| tracing::debug!(error = %err, "dpop_flow failed"))
            .ok()
        else {
            return Ok((false, elapsed_millis_u64(&start)));
        };

        self.cached_access_token = Some(token.access_token);

        Ok((true, elapsed_millis_u64(&start)))
    }

    /// Execute an OIDC userinfo request using a sender-constrained access token.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn userinfo_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let access_token = match self.ensure_userinfo_access_token().await {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(error = %err, "userinfo_flow failed to obtain token");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let success = match self
            .submit_userinfo_request(&access_token, None, "userinfo_flow")
            .await
        {
            TokenExchangeOutcome::Success(_) => true,
            TokenExchangeOutcome::Failure => false,
            TokenExchangeOutcome::DpopNonceChallenge(nonce) => {
                matches!(
                    self.submit_userinfo_request(&access_token, Some(&nonce), "userinfo_flow")
                        .await,
                    TokenExchangeOutcome::Success(_)
                )
            }
        };

        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute a userinfo request that should be rejected for a missing Authorization header.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn userinfo_requires_authorization_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let response = match self
            .client
            .get(self.userinfo_endpoint())
            .header("Forwarded", &self.forwarded_header)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "unauthenticated userinfo request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        let success = is_userinfo_missing_authorization(status);
        if !success {
            tracing::debug!(
                status = %status,
                body = %body_text,
                "unauthenticated userinfo request did not receive the expected rejection"
            );
        }

        Ok((success, elapsed_millis_u64(&start)))
    }

    /// Execute a PAR flow.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn par_flow(&mut self) -> Result<(bool, u64)> {
        let start = Instant::now();
        let (pkce, par_params) = self.authorization_code_params();
        let Some(par_body) = self.request_par_uri(par_params).await else {
            return Ok((false, elapsed_millis_u64(&start)));
        };

        // Step 2: Use request_uri in authorization
        let auth_params = vec![
            ("client_id".to_string(), self.client_profile.id.clone()),
            ("request_uri".to_string(), par_body.request_uri),
        ];
        let Some(auth_body) = self
            .request_authorization_code(&auth_params, "par_flow")
            .await
        else {
            return Ok((false, elapsed_millis_u64(&start)));
        };

        // Step 3: Token exchange using issued code
        let token_endpoint = self.token_proof_htu();
        let Some(token) = self
            .exchange_authorization_code(
                auth_body.code,
                pkce.verifier,
                Some(token_endpoint.as_str()),
                "par_flow",
            )
            .await
        else {
            return Ok((false, elapsed_millis_u64(&start)));
        };

        self.cached_access_token = Some(token.access_token);

        Ok((true, elapsed_millis_u64(&start)))
    }

    /// Execute the key-rotation test flow.
    ///
    /// # Errors
    ///
    /// Returns an error when request construction fails locally.
    pub async fn key_rotation_flow(&self) -> Result<(bool, u64)> {
        let start = Instant::now();

        // Trigger key rotation (admin endpoint)
        let rotation_response = match self
            .client
            .post(format!("{}/admin/rotate-keys", self.base_url))
            .query(&[("type", "all")])
            .header("Forwarded", &self.forwarded_header)
            .basic_auth("admin", Some("admin-secret"))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "key rotation request failed to send");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        if !rotation_response.status().is_success() {
            return Ok((false, elapsed_millis_u64(&start)));
        }

        // Verify new keys are available via JWKS endpoint
        let jwks_response = match self
            .client
            .get(format!("{}/.well-known/jwks.json", self.base_url))
            .header("Forwarded", &self.forwarded_header)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err, "jwks request failed to send after rotation");
                return Ok((false, elapsed_millis_u64(&start)));
            }
        };

        let latency = elapsed_millis_u64(&start);
        Ok((jwks_response.status().is_success(), latency))
    }

    /// Execute the mixed scenario rotation.
    ///
    /// # Errors
    ///
    /// Returns an error when one of the selected scenario helpers fails during local request
    /// construction.
    pub async fn mixed_flow(&mut self, iteration: u64) -> Result<(TestScenario, bool, u64)> {
        // Rotate through baseline scenarios that are expected to succeed against the default server.
        match iteration % 4 {
            0 => {
                let (ok, latency) = self.dpop_flow().await?;
                Ok((TestScenario::DPoP, ok, latency))
            }
            1 => {
                let (ok, latency) = self.introspection_flow().await?;
                Ok((TestScenario::Introspection, ok, latency))
            }
            2 => {
                let (ok, latency) = self.revocation_flow().await?;
                Ok((TestScenario::Revocation, ok, latency))
            }
            _ => {
                let (ok, latency) = self.par_flow().await?;
                Ok((TestScenario::PAR, ok, latency))
            }
        }
    }

    /// Execute the mixed success-path and policy-rejection rotation.
    ///
    /// # Errors
    ///
    /// Returns an error when one of the selected scenario helpers fails during local request
    /// construction.
    pub async fn policy_mixed_flow(&mut self, iteration: u64) -> Result<(TestScenario, bool, u64)> {
        match iteration % 6 {
            0 => {
                let (ok, latency) = self.introspection_flow().await?;
                Ok((TestScenario::Introspection, ok, latency))
            }
            1 => {
                let (ok, latency) = self.introspection_requires_auth_flow().await?;
                Ok((TestScenario::Introspection, ok, latency))
            }
            2 => {
                let (ok, latency) = self.revocation_flow().await?;
                Ok((TestScenario::Revocation, ok, latency))
            }
            3 => {
                let (ok, latency) = self.revocation_requires_auth_flow().await?;
                Ok((TestScenario::Revocation, ok, latency))
            }
            4 => {
                let (ok, latency) = self.userinfo_flow().await?;
                Ok((TestScenario::Userinfo, ok, latency))
            }
            _ => {
                let (ok, latency) = self.userinfo_requires_authorization_flow().await?;
                Ok((TestScenario::Userinfo, ok, latency))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};

    fn invalid_client_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"token\", error=\"invalid_client\""),
        );
        headers
    }

    #[test]
    fn introspection_rejection_requires_invalid_client_body() {
        let headers = invalid_client_headers();
        let error = OAuthErrorResponse {
            error: Some("invalid_client".to_string()),
            error_description: None,
        };

        assert!(is_unauthenticated_introspection_rejection(
            StatusCode::UNAUTHORIZED,
            &headers,
            &error
        ));

        let wrong_error = OAuthErrorResponse {
            error: Some("invalid_request".to_string()),
            error_description: None,
        };
        assert!(!is_unauthenticated_introspection_rejection(
            StatusCode::UNAUTHORIZED,
            &headers,
            &wrong_error
        ));
    }

    #[test]
    fn revocation_rejection_requires_invalid_client_header() {
        let headers = invalid_client_headers();
        assert!(is_unauthenticated_revocation_rejection(
            StatusCode::UNAUTHORIZED,
            &headers
        ));
        assert!(!is_unauthenticated_revocation_rejection(
            StatusCode::BAD_REQUEST,
            &headers
        ));
    }

    #[test]
    fn userinfo_rejection_is_unauthorized_only() {
        assert!(is_userinfo_missing_authorization(StatusCode::UNAUTHORIZED));
        assert!(!is_userinfo_missing_authorization(StatusCode::NOT_FOUND));
    }
}
