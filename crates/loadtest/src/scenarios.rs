use crate::{
    accounting::HttpAccounting,
    generator::{PkcePair, TestDataGenerator},
    oidc::verify_id_token,
    profile::{scopes, sha256, ClientAuth, ClientProfile, ParPolicy, SenderPolicy},
    TestScenario,
};
use anyhow::{bail, ensure, Context, Result};
use reqwest::{
    header::{HeaderMap, LOCATION, WWW_AUTHENTICATE},
    Client, RequestBuilder, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub sub: Option<String>,
    pub exp: Option<u64>,
    pub aud: Option<serde_json::Value>,
    pub cnf: Option<serde_json::Value>,
    pub iss: Option<String>,
}

#[derive(Deserialize)]
struct Userinfo {
    sub: String,
}

#[derive(Deserialize)]
struct ParSuccess {
    request_uri: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

struct WireResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct Transaction {
    pkce: PkcePair,
    state: String,
    nonce: Option<String>,
    scope: String,
    resource: Option<String>,
    params: Vec<(String, String)>,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    scope: String,
    resource: Option<String>,
    subject: Option<String>,
    expires: Instant,
}

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

fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .context("required response header is missing")?
        .to_str()?;
    ensure!(
        values.next().is_none() && !value.is_empty(),
        "ambiguous or empty response header"
    );
    Ok(value)
}

fn authorization_code(
    status: StatusCode,
    headers: &HeaderMap,
    redirect: &str,
    state: &str,
    issuer: &str,
) -> Result<String> {
    ensure!(
        status == StatusCode::FOUND,
        "positive authorization requires HTTP 302"
    );
    let location = one_header(headers, LOCATION.as_str())?;
    let actual = Url::parse(location).context("authorization Location must be absolute")?;
    let registered = Url::parse(redirect)?;
    ensure!(
        actual.scheme() == registered.scheme()
            && actual.host_str() == registered.host_str()
            && actual.port_or_known_default() == registered.port_or_known_default()
            && actual.username().is_empty()
            && actual.password().is_none()
            && actual.path() == registered.path()
            && actual.fragment().is_none(),
        "authorization destination differs from registration"
    );
    let query = location
        .split_once('?')
        .map(|(_, query)| query)
        .context("authorization response query is missing")?;
    let response_query = if let Some((_, static_query)) = redirect.split_once('?') {
        query
            .strip_prefix(static_query)
            .and_then(|suffix| suffix.strip_prefix('&'))
            .context("registered static query was changed or not retained first")?
    } else {
        query
    };
    ensure!(
        response_query.split('&').all(|pair| !pair.is_empty()),
        "empty authorization response query field"
    );
    let mut response_url = actual;
    response_url.set_query(Some(response_query));
    let remaining: Vec<(String, String)> = response_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let unique = |name: &str| -> Result<Option<&str>> {
        let values: Vec<_> = remaining
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect();
        ensure!(
            values.len() <= 1 && values.iter().all(|v| !v.is_empty()),
            "duplicate or empty authorization response parameter"
        );
        Ok(values.first().copied())
    };
    ensure!(
        unique("state")? == Some(state) && unique("iss")? == Some(issuer),
        "authorization state/issuer mismatch"
    );
    let code = unique("code")?;
    let error = unique("error")?;
    ensure!(
        code.is_some() != error.is_some(),
        "authorization must return exactly one code or error"
    );
    for (name, _) in &remaining {
        ensure!(
            [
                "code",
                "state",
                "iss",
                "error",
                "error_description",
                "error_uri"
            ]
            .contains(&name.as_str()),
            "unexpected authorization response parameter"
        );
    }
    unique("error_description")?;
    unique("error_uri")?;
    ensure!(error.is_none(), "authorization returned an OAuth error");
    ensure!(
        remaining.len() == 3,
        "positive authorization response has unexpected fields"
    );
    Ok(code.context("authorization code missing")?.to_owned())
}

fn nonce_challenge(response: &WireResponse, resource_server: bool) -> Result<Option<String>> {
    let expected = if resource_server {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    if response.status != expected {
        return Ok(None);
    }
    let Ok(error) = serde_json::from_slice::<OAuthError>(&response.body) else {
        return Ok(None);
    };
    if error.error != "use_dpop_nonce" {
        return Ok(None);
    }
    if resource_server {
        let header = one_header(&response.headers, WWW_AUTHENTICATE.as_str())?;
        ensure!(
            header.starts_with("DPoP ") && header.contains("error=\"use_dpop_nonce\""),
            "invalid resource-server DPoP challenge"
        );
    }
    Ok(Some(
        one_header(&response.headers, "DPoP-Nonce")?.to_owned(),
    ))
}

fn apply_auth(
    profile: &ClientProfile,
    mut request: RequestBuilder,
    params: &mut Vec<(String, String)>,
) -> RequestBuilder {
    match profile.supply.client_auth {
        ClientAuth::ClientSecretBasic => {
            let id: String =
                form_urlencoded::byte_serialize(profile.supply.client_id.as_bytes()).collect();
            let secret: String =
                form_urlencoded::byte_serialize(profile.secret.as_bytes()).collect();
            request = request.basic_auth(id, Some(secret));
        }
        ClientAuth::ClientSecretPost => {
            if !params.iter().any(|(k, _)| k == "client_id") {
                params.push(("client_id".into(), profile.supply.client_id.clone()));
            }
            params.push(("client_secret".into(), profile.secret.clone()));
        }
    }
    request
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
            executor.discovery_expected_issuer = issuer.to_owned();
        }
        Ok(executor)
    }

    pub fn with_profile(mut base_url: String, profile: Option<ClientProfile>) -> Result<Self> {
        let url = Url::parse(&base_url).context("invalid target URL")?;
        ensure!(
            ["http", "https"].contains(&url.scheme())
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid target URL components"
        );
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

    async fn send(
        &mut self,
        method: &str,
        endpoint: &str,
        request: RequestBuilder,
    ) -> Result<WireResponse> {
        self.accounting.attempts += 1;
        let key = format!("{method} {endpoint}");
        *self
            .accounting
            .methods_endpoints
            .entry(key.clone())
            .or_default() += 1;
        let Ok(mut response) = request.send().await else {
            self.accounting.transport_failures += 1;
            bail!("HTTP transport failed for {key}");
        };
        self.accounting.responses += 1;
        let status = response.status();
        *self
            .accounting
            .statuses
            .entry(format!("{key} {}", status.as_u16()))
            .or_default() += 1;
        let headers = response.headers().clone();
        let mut body = Vec::new();
        if response
            .content_length()
            .is_some_and(|v| v > MAX_BODY_BYTES as u64)
        {
            self.accounting.body_failures += 1;
            bail!("HTTP response exceeds body bound for {key}");
        }
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= MAX_BODY_BYTES => {
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                _ => {
                    self.accounting.body_failures += 1;
                    bail!("HTTP response body failed for {key}");
                }
            }
        }
        Ok(WireResponse {
            status,
            headers,
            body,
        })
    }

    fn transaction(&mut self, scope: String, resource: Option<String>) -> Result<Transaction> {
        let profile = self.profile()?.clone();
        let state = self.generator.state();
        let pkce = self.generator.pkce_pair();
        let nonce = scopes(&scope)?
            .contains("openid")
            .then(|| self.generator.nonce());
        let mut params = vec![
            ("response_type".into(), "code".into()),
            ("response_mode".into(), "query".into()),
            ("prompt".into(), "none".into()),
            ("iss".into(), profile.supply.issuer.clone()),
            ("client_id".into(), profile.supply.client_id),
            ("redirect_uri".into(), profile.supply.redirect_uri),
            ("scope".into(), scope.clone()),
            ("state".into(), state.clone()),
            ("code_challenge".into(), pkce.challenge.clone()),
            ("code_challenge_method".into(), "S256".into()),
        ];
        if let Some(value) = &nonce {
            params.push(("nonce".into(), value.clone()));
        }
        if let Some(value) = &resource {
            params.push(("resource".into(), value.clone()));
        }
        Ok(Transaction {
            pkce,
            state,
            nonce,
            scope,
            resource,
            params,
        })
    }

    async fn authorization_params(
        &mut self,
        profile: &ClientProfile,
        tx: &Transaction,
        force_par: bool,
    ) -> Result<Vec<(String, String)>> {
        let params = if force_par || profile.supply.par_policy == ParPolicy::Required {
            let mut params = tx.params.clone();
            let request = apply_auth(
                profile,
                self.client.post(format!("{}/par", self.base_url)),
                &mut params,
            )
            .form(&params);
            let response = self.send("POST", "/par", request).await?;
            ensure!(
                response.status == StatusCode::CREATED,
                "PAR must return HTTP 201"
            );
            let par: ParSuccess =
                serde_json::from_slice(&response.body).context("invalid PAR response")?;
            ensure!(
                !par.request_uri.trim().is_empty() && par.expires_in > 0,
                "empty or expired PAR response"
            );
            vec![
                ("client_id".into(), profile.supply.client_id.clone()),
                ("request_uri".into(), par.request_uri),
            ]
        } else {
            tx.params.clone()
        };
        Ok(params)
    }

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

    fn validate_access_token(
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

    async fn issue_token(&mut self, oidc: bool, force_par: bool) -> Result<CachedToken> {
        let profile = self.profile()?.clone();
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

    async fn ensure_token(&mut self, oidc: bool) -> Result<CachedToken> {
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
            serde_json::from_slice(&response.body).context("invalid introspection response")?;
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
        self.cached_access_token = None;
        let mut params = vec![("token".into(), token.access_token)];
        let request = apply_auth(
            &profile,
            self.client.post(format!("{}/introspect", self.base_url)),
            &mut params,
        )
        .form(&params);
        let response = self.send("POST", "/introspect", request).await?;
        ensure!(
            response.status == StatusCode::OK
                && !serde_json::from_slice::<IntrospectionResponse>(&response.body)?.active,
            "revoked token remains active"
        );
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
            let value: Userinfo =
                serde_json::from_slice(&response.body).context("invalid UserInfo response")?;
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
                serde_json::from_slice::<OAuthError>(&response.body)?.error == "invalid_client",
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
        let metadata: serde_json::Value = serde_json::from_slice(&response.body)?;
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
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&response.body)?;
        ensure!(!jwks.keys.is_empty(), "JWKS has no activated signing keys");
        Ok((true, elapsed(start)))
    }
    pub fn key_rotation_flow(&mut self) -> Result<(bool, u64)> {
        bail!(
            "key-rotation is unsupported: HUMAN/NEXT/restart supervisor contract remains required"
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;
    fn test_profile(auth: ClientAuth) -> ClientProfile {
        let supply = serde_json::from_value(serde_json::json!({"issuer":"https://issuer.example.test",
            "environment_id":"e","configuration_version_id":"v","oauth_profile_id":"p","activation":"ACTIVE",
            "client_id":"client+ id","redirect_uri":"https://client.example.test/cb","client_auth":auth,
            "scope":"read","subject":"subject","sender_policy":"dpop","par_policy":"required"})).unwrap();
        ClientProfile {
            supply,
            secret: "secret+ %:é".into(),
            session_cookie: HeaderValue::from_static("aegaeon_auth_session=private"),
            profile_sha256: "a".repeat(64),
            session_provenance_sha256: "b".repeat(64),
        }
    }
    #[test]
    fn explicit_auth_method_uses_one_wire_location_and_encodes_basic_once() {
        use base64::Engine;
        for auth in [ClientAuth::ClientSecretBasic, ClientAuth::ClientSecretPost] {
            let profile = test_profile(auth);
            let mut params = vec![("token".into(), "a+b %:é".into())];
            let request = apply_auth(
                &profile,
                Client::new().post("https://issuer.example.test/token"),
                &mut params,
            )
            .form(&params)
            .build()
            .unwrap();
            assert!(!request.headers().contains_key(reqwest::header::COOKIE));
            assert!(!request.headers().contains_key("Forwarded"));
            let form: Vec<_> =
                form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap()).collect();
            if auth == ClientAuth::ClientSecretBasic {
                let header = &request.headers()[reqwest::header::AUTHORIZATION];
                assert!(header.is_sensitive());
                let encoded = header.to_str().unwrap().strip_prefix("Basic ").unwrap();
                let wire = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap();
                assert_eq!(wire, b"client%2B+id:secret%2B+%25%3A%C3%A9");
                assert_eq!(form.len(), 1);
            } else {
                assert!(!request
                    .headers()
                    .contains_key(reqwest::header::AUTHORIZATION));
                assert_eq!(form.iter().filter(|(k, _)| k == "client_secret").count(), 1);
                assert!(form
                    .iter()
                    .any(|(k, v)| k == "client_secret" && v == "secret+ %:é"));
                assert!(form
                    .iter()
                    .any(|(k, v)| k == "client_id" && v == "client+ id"));
            }
        }
    }
    #[tokio::test]
    async fn client_records_302_without_following_or_contacting_callback() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let issuer = TcpListener::bind("127.0.0.1:0").unwrap();
        let callback = TcpListener::bind("127.0.0.1:0").unwrap();
        callback.set_nonblocking(true).unwrap();
        let base = format!("http://{}", issuer.local_addr().unwrap());
        let destination = format!("http://{}/callback", callback.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = issuer.accept().unwrap();
            let mut bytes = [0; 4096];
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut bytes).unwrap();
                assert!(count > 0, "request ended before its headers");
                request.extend_from_slice(&bytes[..count]);
                assert!(
                    request.len() <= 16 * 1024,
                    "request headers exceed fixture bound"
                );
            }
            stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {destination}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        });
        let mut executor = ScenarioExecutor::with_profile(base.clone(), None).unwrap();
        let response = executor
            .send(
                "GET",
                "/authorize",
                executor.client.get(format!("{base}/authorize")),
            )
            .await
            .unwrap();
        thread.join().unwrap();
        assert_eq!(response.status, StatusCode::FOUND);
        assert_eq!(
            callback.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 1);
    }
    #[test]
    fn authorization_redirect_requires_bound_destination_unique_state_issuer_and_code() {
        let mut headers = HeaderMap::new();
        let redirect = "https://client.example.test/callback?fixed=1";
        let good = "https://client.example.test/callback?fixed=1&code=code&state=state&iss=https%3A%2F%2Fissuer.example.test";
        headers.insert(LOCATION, HeaderValue::from_str(good).unwrap());
        assert_eq!(
            authorization_code(
                StatusCode::FOUND,
                &headers,
                redirect,
                "state",
                "https://issuer.example.test"
            )
            .unwrap(),
            "code"
        );
        assert!(authorization_code(
            StatusCode::OK,
            &headers,
            redirect,
            "state",
            "https://issuer.example.test"
        )
        .is_err());
        for bad in [
            good.replace("fixed=1", "fixed=2"),
            good.replace("client.example.test", "evil.example.test"),
            good.replace("state=state", "state=state&state=state"),
            good.replace("code=code", "code=code&error=denied"),
            good.replace("state=state", "state=wrong"),
            good.replace("issuer.example.test", "other.example.test"),
            format!("{good}#fragment"),
        ] {
            headers.insert(LOCATION, HeaderValue::from_str(&bad).unwrap());
            assert!(authorization_code(
                StatusCode::FOUND,
                &headers,
                redirect,
                "state",
                "https://issuer.example.test"
            )
            .is_err());
        }
        headers.insert(LOCATION, HeaderValue::from_str(good).unwrap());
        headers.append(LOCATION, HeaderValue::from_str(good).unwrap());
        assert!(authorization_code(
            StatusCode::FOUND,
            &headers,
            redirect,
            "state",
            "https://issuer.example.test"
        )
        .is_err());
    }
    #[test]
    fn authorization_redirect_retains_raw_registered_query_before_response() {
        let response = "code=code&state=state&iss=https%3A%2F%2Fissuer.example.test";
        for registered in [
            "https://client.example.test/callback",
            "https://client.example.test/callback?",
            "https://client.example.test/callback?fixed=one%20two&other=%2f%3D&flag&empty=",
            "https://client.example.test/callback?fixed=1&",
        ] {
            let separator = if registered.contains('?') { '&' } else { '?' };
            let location = format!("{registered}{separator}{response}");
            let mut headers = HeaderMap::new();
            headers.insert(LOCATION, HeaderValue::from_str(&location).unwrap());
            assert_eq!(
                authorization_code(
                    StatusCode::FOUND,
                    &headers,
                    registered,
                    "state",
                    "https://issuer.example.test"
                )
                .unwrap(),
                "code"
            );
        }
    }
    #[test]
    fn authorization_redirect_rejects_reencoded_reordered_or_extra_static_query() {
        let registered = "https://client.example.test/callback?fixed=one%20two&other=%2f%3D";
        let response = "code=code&state=state&iss=https%3A%2F%2Fissuer.example.test";
        let good_query = "fixed=one%20two&other=%2f%3D";
        for query in [
            format!("fixed=one+two&other=%2f%3D&{response}"),
            format!("fixed=one%20two&other=%2F%3D&{response}"),
            format!("other=%2f%3D&fixed=one%20two&{response}"),
            format!("fixed=changed&other=%2f%3D&{response}"),
            format!("{good_query}changed&{response}"),
            format!("{response}&{good_query}"),
            format!("{good_query}&fixed=one%20two&{response}"),
            format!("{good_query}&extra=1&{response}"),
            format!("{good_query}&{response}&other=%2f%3D"),
            format!("{good_query}&{response}&code=extra"),
            format!("{good_query}&{response}&state=state"),
            format!("{good_query}&{response}&error_description=unexpected"),
            format!("{good_query}&{response}&"),
            format!("{good_query}&&{response}"),
        ] {
            let location = format!("https://client.example.test/callback?{query}");
            let mut headers = HeaderMap::new();
            headers.insert(LOCATION, HeaderValue::from_str(&location).unwrap());
            assert!(
                authorization_code(
                    StatusCode::FOUND,
                    &headers,
                    registered,
                    "state",
                    "https://issuer.example.test"
                )
                .is_err(),
                "accepted altered query: {query}"
            );
        }
    }
    #[test]
    fn nonce_challenge_distinguishes_as400_and_rs401_and_requires_header() {
        let mut response = WireResponse {
            status: StatusCode::BAD_REQUEST,
            headers: HeaderMap::new(),
            body: br#"{"error":"use_dpop_nonce"}"#.to_vec(),
        };
        assert!(nonce_challenge(&response, false).is_err());
        response
            .headers
            .insert("DPoP-Nonce", HeaderValue::from_static("nonce"));
        assert_eq!(
            nonce_challenge(&response, false).unwrap(),
            Some("nonce".into())
        );
        assert_eq!(nonce_challenge(&response, true).unwrap(), None);
        response.status = StatusCode::UNAUTHORIZED;
        assert!(nonce_challenge(&response, true).is_err());
        response.headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP error=\"use_dpop_nonce\""),
        );
        assert_eq!(
            nonce_challenge(&response, true).unwrap(),
            Some("nonce".into())
        );
        response
            .headers
            .append("DPoP-Nonce", HeaderValue::from_static("second"));
        assert!(nonce_challenge(&response, true).is_err());
    }

    struct FixtureReply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn fixture_reply(status: u16, body: Vec<u8>) -> FixtureReply {
        FixtureReply {
            status,
            headers: Vec::new(),
            body,
        }
    }

    fn http_fixture(
        steps: usize,
        mut handler: impl FnMut(usize, &str, &str) -> FixtureReply + Send + 'static,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server_base = base.clone();
        let thread = std::thread::spawn(move || {
            for step in 0..steps {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "fixture request was not sent");
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("fixture accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut bytes = [0; 4096];
                loop {
                    let count = stream.read(&mut bytes).unwrap();
                    assert!(count > 0, "fixture request ended prematurely");
                    request.extend_from_slice(&bytes[..count]);
                    assert!(request.len() <= 16 * 1024);
                    if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let reply = handler(step, std::str::from_utf8(&request).unwrap(), &server_base);
                let mut headers = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in reply.headers {
                    use std::fmt::Write as _;
                    write!(headers, "{name}: {value}\r\n").unwrap();
                }
                stream.write_all(headers.as_bytes()).unwrap();
                stream.write_all(b"\r\n").unwrap();
                stream.write_all(&reply.body).unwrap();
            }
        });
        (base, thread)
    }

    fn fixture_profile(base: &str, oidc: bool) -> ClientProfile {
        let mut profile = test_profile(ClientAuth::ClientSecretBasic);
        profile.supply.issuer = base.to_owned();
        profile.supply.par_policy = ParPolicy::Optional;
        if oidc {
            profile.supply.oidc_scope = Some("openid".into());
            profile.supply.id_token_alg = Some("RS256".into());
        }
        profile
    }

    fn authorization_fixture_reply(request: &str, base: &str) -> (FixtureReply, Option<String>) {
        let path = request.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&format!("{base}{path}")).unwrap();
        assert_eq!(url.path(), "/authorize");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let mut redirect = Url::parse(&query["redirect_uri"]).unwrap();
        redirect
            .query_pairs_mut()
            .append_pair("code", "code")
            .append_pair("state", &query["state"])
            .append_pair("iss", base);
        let mut reply = fixture_reply(302, Vec::new());
        reply
            .headers
            .push(("Location".into(), redirect.to_string()));
        (reply, query.get("nonce").cloned())
    }

    fn fixture_token(oidc: bool, expiry: u64) -> serde_json::Value {
        serde_json::json!({"access_token":"token","token_type":"DPoP","expires_in":expiry,
            "scope":if oidc { "openid" } else { "read" }})
    }

    #[tokio::test]
    async fn discovery_requires_advertised_jwks_and_exact_issuer_and_token_endpoint() {
        for changed in [
            None,
            Some("issuer"),
            Some("token_endpoint"),
            Some("jwks_uri"),
            Some("alias"),
        ] {
            let (base, thread) = http_fixture(1, move |_, request, base| {
                assert!(request.starts_with("GET /.well-known/oauth-authorization-server "));
                let mut metadata = serde_json::json!({"issuer":base,"token_endpoint":format!("{base}/token"),"jwks_uri":format!("{base}/jwks")});
                if let Some(field) = changed {
                    if field == "alias" {
                        metadata["jwks_uri"] = format!("{base}/.well-known/jwks.json").into();
                    } else {
                        metadata[field] = "https://other.example.test/endpoint".into();
                    }
                }
                fixture_reply(200, serde_json::to_vec(&metadata).unwrap())
            });
            let mut executor = ScenarioExecutor::with_profile(base, None).unwrap();
            assert_eq!(executor.discovery_flow().await.is_ok(), changed.is_none());
            thread.join().unwrap();
            let accounting = executor.take_accounting();
            accounting.validate().unwrap();
            assert_eq!(accounting.attempts, 1);
        }
    }

    #[tokio::test]
    async fn discovery_http_transport_checks_independent_https_issuer_and_endpoints() {
        for changed in [
            None,
            Some("issuer"),
            Some("token_endpoint"),
            Some("jwks_uri"),
        ] {
            let canonical = "https://issuer.example.test/tenant";
            let (base, thread) = http_fixture(1, move |_, request, _| {
                assert!(request.starts_with("GET /.well-known/oauth-authorization-server "));
                let mut metadata = serde_json::json!({"issuer":canonical,
                    "token_endpoint":format!("{canonical}/token"),
                    "jwks_uri":format!("{canonical}/jwks")});
                if let Some(field) = changed {
                    metadata[field] = "https://other.example.test/endpoint".into();
                }
                fixture_reply(200, serde_json::to_vec(&metadata).unwrap())
            });
            let prototype = ScenarioExecutor::for_scenario_with_discovery_issuer(
                base,
                &TestScenario::Discovery,
                Some(canonical),
            )
            .unwrap();
            let mut executor = prototype.fork_worker();
            assert_eq!(executor.discovery_flow().await.is_ok(), changed.is_none());
            thread.join().unwrap();
            let accounting = executor.take_accounting();
            accounting.validate().unwrap();
            assert_eq!(accounting.attempts, 1);
        }
    }

    #[test]
    fn discovery_canonical_issuer_rejects_unsafe_urls_and_preserves_credential_target() {
        for issuer in [
            "http://issuer.example.test",
            "https://issuer.example.test/",
            "https://user:secret@issuer.example.test",
            "https://issuer.example.test?query",
            "https://issuer.example.test#fragment",
            "https://ISSUER.example.test",
            "not-a-url",
        ] {
            assert!(ScenarioExecutor::for_scenario_with_discovery_issuer(
                "http://127.0.0.1:18095".into(),
                &TestScenario::Discovery,
                Some(issuer),
            )
            .is_err());
        }
        let profile = fixture_profile("https://issuer.example.test", false);
        assert!(profile
            .supply
            .validate("https://issuer.example.test", false, false)
            .is_ok());
        for target in [
            "http://127.0.0.1:18095",
            "http://issuer.example.test",
            "https://other.example.test",
            "https://issuer.example.test/",
        ] {
            assert!(profile.supply.validate(target, false, false).is_err());
        }
    }

    #[tokio::test]
    async fn standalone_jwks_digest_identifies_latest_success_or_failed_body() {
        let bodies = [
            (
                200,
                br#"{"keys":[{"kty":"oct","k":"AQAB"}]}"#.to_vec(),
                true,
            ),
            (503, b"unavailable".to_vec(), false),
            (200, b"invalid JSON".to_vec(), false),
            (200, br#"{"keys":[]}"#.to_vec(), false),
        ];
        let expected: Vec<_> = bodies
            .iter()
            .map(|(_, body, success)| (sha256(body), *success))
            .collect();
        let (base, thread) = http_fixture(bodies.len(), move |index, request, _| {
            assert!(request.starts_with("GET /.well-known/jwks.json "));
            fixture_reply(bodies[index].0, bodies[index].1.clone())
        });
        let mut executor = ScenarioExecutor::with_profile(base, None).unwrap();
        executor.jwks_sha256 = Some(sha256(b"previous accepted body"));
        for (digest, success) in expected {
            assert_eq!(executor.jwks_flow().await.is_ok(), success);
            assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
        }
        thread.join().unwrap();
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 4);
    }

    #[tokio::test]
    async fn oidc_failure_records_received_jwks_before_status_or_verification() {
        for (status, body) in [
            (503, b"unavailable".to_vec()),
            (200, b"invalid JSON".to_vec()),
            (200, br#"{"keys":[]}"#.to_vec()),
        ] {
            let digest = sha256(&body);
            let (base, thread) = http_fixture(3, move |step, request, base| match step {
                0 => authorization_fixture_reply(request, base).0,
                1 => {
                    assert!(request.starts_with("POST /token "));
                    let mut token = fixture_token(true, 300);
                    token["id_token"] = "invalid.signature.token".into();
                    fixture_reply(200, serde_json::to_vec(&token).unwrap())
                }
                _ => {
                    assert!(request.starts_with("GET /.well-known/jwks.json "));
                    fixture_reply(status, body.clone())
                }
            });
            let mut executor =
                ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true)))
                    .unwrap();
            executor.jwks_sha256 = Some(sha256(b"previous accepted body"));
            assert!(executor.ensure_token(true).await.is_err());
            assert!(executor.cached_userinfo_access_token.is_none());
            assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
            thread.join().unwrap();
            let accounting = executor.take_accounting();
            accounting.validate().unwrap();
            assert_eq!(accounting.attempts, 3);
        }
    }

    fn rsa_fixture_key() -> (jsonwebtoken::EncodingKey, Vec<u8>) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use std::{fs, process::Command};
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory =
            std::env::temp_dir().join(format!("aegaeon-loadtest-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let _cleanup = Cleanup(directory.clone());
        let key = directory.join("key.pem");
        let generated = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(generated.status.success());
        let modulus = Command::new("openssl")
            .args(["rsa", "-modulus", "-noout", "-in"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(modulus.status.success());
        let hex = String::from_utf8(modulus.stdout).unwrap();
        let hex = hex.trim().strip_prefix("Modulus=").unwrap();
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let jwks = serde_json::to_vec(&serde_json::json!({"keys":[{"kty":"RSA","kid":"signing","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(bytes),"e":"AQAB"}]})).unwrap();
        (
            jsonwebtoken::EncodingKey::from_rsa_pem(&fs::read(key).unwrap()).unwrap(),
            jwks,
        )
    }

    #[tokio::test]
    async fn token_deadline_includes_nonce_retry_and_delayed_jwks_without_stale_reuse() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let (key, jwks) = rsa_fixture_key();
        let expected_digest = sha256(&jwks);
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut nonce = String::new();
        let (base, thread) = http_fixture(7, move |step, request, base| match step {
            0 | 4 => {
                let (reply, received_nonce) = authorization_fixture_reply(request, base);
                nonce = received_nonce.unwrap();
                reply
            }
            1 => {
                assert!(request.starts_with("POST /token "));
                sender.send(Instant::now()).unwrap();
                std::thread::sleep(Duration::from_millis(100));
                let mut reply = fixture_reply(400, br#"{"error":"use_dpop_nonce"}"#.to_vec());
                reply
                    .headers
                    .push(("DPoP-Nonce".into(), uuid::Uuid::new_v4().to_string()));
                reply
            }
            2 | 5 => {
                assert!(request.starts_with("POST /token "));
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let claims = serde_json::json!({"iss":base,"sub":"subject","aud":"client+ id","nonce":nonce,"iat":now,"exp":now+300});
                let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                header.kid = Some("signing".into());
                let id = jsonwebtoken::encode(&header, &claims, &key).unwrap();
                let mut token = fixture_token(true, 1);
                token["id_token"] = id.into();
                fixture_reply(200, serde_json::to_vec(&token).unwrap())
            }
            _ => {
                assert!(request.starts_with("GET /.well-known/jwks.json "));
                if step == 3 {
                    std::thread::sleep(Duration::from_millis(1200));
                }
                fixture_reply(200, jwks.clone())
            }
        });
        let mut executor =
            ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true)))
                .unwrap();
        let error = executor.ensure_token(true).await.err().unwrap();
        let first_request = receiver.recv().unwrap();
        assert!(first_request + Duration::from_secs(1) <= Instant::now());
        assert!(error.to_string().contains("token expired before delivery"));
        assert!(executor.cached_userinfo_access_token.is_none());
        assert_eq!(
            executor.jwks_sha256.as_deref(),
            Some(expected_digest.as_str())
        );
        executor.accounting.validate().unwrap();
        assert_eq!(executor.accounting.attempts, 4);
        let replacement = executor.ensure_token(true).await.unwrap();
        assert!(replacement.expires > Instant::now());
        assert_eq!(replacement.subject.as_deref(), Some("subject"));
        assert!(executor.cached_userinfo_access_token.is_some());
        assert_eq!(
            executor.jwks_sha256.as_deref(),
            Some(expected_digest.as_str())
        );
        thread.join().unwrap();
        let accounting = executor.take_accounting();
        accounting.validate().unwrap();
        assert_eq!(accounting.attempts, 7);
        assert_eq!(accounting.nonce_challenges["authorization_server"], 1);
        assert_eq!(accounting.nonce_retries["authorization_server"], 1);
    }

    #[tokio::test]
    async fn token_expiry_and_sender_scope_validation_remain_fatal() {
        for field in [
            "zero",
            "missing",
            "overflow",
            "token_type",
            "scope",
            "refresh_token",
            "access_token",
        ] {
            let (base, thread) = http_fixture(2, move |step, request, base| {
                if step == 0 {
                    return authorization_fixture_reply(request, base).0;
                }
                assert!(request.starts_with("POST /token "));
                let mut token = fixture_token(false, 300);
                match field {
                    "zero" => token["expires_in"] = 0.into(),
                    "missing" => token
                        .as_object_mut()
                        .unwrap()
                        .remove("expires_in")
                        .map(|_| ())
                        .unwrap(),
                    "overflow" => token["expires_in"] = u64::MAX.into(),
                    "token_type" => token["token_type"] = "Bearer".into(),
                    "scope" => token["scope"] = "other".into(),
                    "refresh_token" => token["refresh_token"] = "unexpected".into(),
                    _ => token["access_token"] = "".into(),
                }
                fixture_reply(200, serde_json::to_vec(&token).unwrap())
            });
            let mut executor =
                ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, false)))
                    .unwrap();
            assert!(
                executor.ensure_token(false).await.is_err(),
                "accepted {field}"
            );
            assert!(executor.cached_access_token.is_none());
            thread.join().unwrap();
            let accounting = executor.take_accounting();
            accounting.validate().unwrap();
            assert_eq!(accounting.attempts, 2);
        }
    }
}
