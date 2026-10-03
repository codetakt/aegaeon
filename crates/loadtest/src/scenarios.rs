use crate::{
    accounting::HttpAccounting,
    generator::{PkcePair, TestDataGenerator},
    oidc::verify_id_token,
    profile::{scopes, ClientAuth, ClientProfile, ParPolicy, SenderPolicy},
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
        Self::with_profile(base_url, profile)
    }

    pub fn with_profile(base_url: String, profile: Option<ClientProfile>) -> Result<Self> {
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
        Ok(Self {
            client: builder.build()?,
            base_url: base_url.trim_end_matches('/').into(),
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

    pub fn fork_worker(&self) -> Self {
        Self {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
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
        let mut response = match request.send().await {
            Ok(response) => response,
            Err(_) => {
                self.accounting.transport_failures += 1;
                bail!("HTTP transport failed for {key}");
            }
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
                    body.extend_from_slice(&chunk)
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
        let params = if force_par || profile.supply.par_policy == ParPolicy::Required {
            let mut params = tx.params.clone();
            let request = apply_auth(
                &profile,
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
        let mut nonce = None;
        let mut token = None;
        for attempt in 0..2 {
            let mut request = self.client.post(format!("{}/token", self.base_url));
            let mut wire_params = params.clone();
            request = apply_auth(&profile, request, &mut wire_params).form(&wire_params);
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
        let effective: String = tx
            .scope
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
            ensure!(response.status == StatusCode::OK, "JWKS requires HTTP 200");
            let (subject, digest) = verify_id_token(
                id,
                &response.body,
                &profile.supply,
                &expected_nonce,
                &token.access_token,
                &code,
            )?;
            self.jwks_sha256 = Some(digest);
            Some(subject)
        } else {
            ensure!(
                token.id_token.is_none(),
                "unexpected ID Token without openid transaction"
            );
            None
        };
        Ok(CachedToken {
            access_token: token.access_token,
            scope: effective,
            resource: tx.resource,
            subject,
            expires: Instant::now()
                .checked_add(Duration::from_secs(ttl))
                .context("token expiry exceeds clock range")?,
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
            #[derive(Deserialize)]
            struct Userinfo {
                sub: String,
            }
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
            metadata["issuer"].as_str() == Some(&self.base_url)
                && metadata["token_endpoint"].as_str()
                    == Some(format!("{}/token", self.base_url).as_str())
                && metadata["jwks_uri"].as_str()
                    == Some(format!("{}/.well-known/jwks.json", self.base_url).as_str()),
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
        ensure!(response.status == StatusCode::OK, "JWKS requires HTTP 200");
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&response.body)?;
        ensure!(!jwks.keys.is_empty(), "JWKS has no activated signing keys");
        Ok((true, elapsed(start)))
    }
    pub async fn key_rotation_flow(&mut self) -> Result<(bool, u64)> {
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
            stream.read(&mut bytes).unwrap();
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
}
