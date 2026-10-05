//! HTTP response bounds, OAuth wire types and credential placement.
use super::ScenarioExecutor;
use crate::profile::{ClientAuth, ClientProfile};
use anyhow::{bail, ensure, Context, Result};
use reqwest::{
    header::{HeaderMap, WWW_AUTHENTICATE},
    RequestBuilder, StatusCode,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

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
pub(super) struct Userinfo {
    pub(super) sub: String,
}

#[derive(Deserialize)]
pub(super) struct ParSuccess {
    pub(super) request_uri: String,
    pub(super) expires_in: u64,
}

#[derive(Deserialize)]
pub(super) struct OAuthError {
    pub(super) error: String,
}

pub(super) struct WireResponse {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

pub(super) fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub(super) fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
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

pub(super) fn nonce_challenge(
    response: &WireResponse,
    resource_server: bool,
) -> Result<Option<String>> {
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

pub(super) fn apply_auth(
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
    pub(super) async fn send(
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
}
