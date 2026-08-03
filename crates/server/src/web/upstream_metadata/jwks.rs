use super::super::UPSTREAM_MAX_BODY_BYTES;
use super::validate_upstream_outbound_url;
use aegaeon_jose::jwk::JwkSet;
use reqwest::Client;
use serde_json::Value;

use crate::upstream::NonAuthoritativeMetadataCache;
use crate::util;

pub(in crate::web) fn parse_upstream_jwks_body(body: &[u8]) -> Result<JwkSet, String> {
    util::validate_json_without_duplicate_object_keys(body).map_err(|err| match err {
        util::JsonAdmissionError::DuplicateKey => {
            "upstream jwks response contains duplicate object keys".to_string()
        }
        util::JsonAdmissionError::InvalidJson | util::JsonAdmissionError::TrailingBytes => {
            "upstream jwks response invalid".to_string()
        }
    })?;
    let value = serde_json::from_slice::<Value>(body)
        .map_err(|_| "upstream jwks response invalid".to_string())?;
    let jwks = JwkSet::from_value(value).map_err(|err| format!("upstream jwks invalid: {err}"))?;
    jwks.ensure_unique_kid()
        .map_err(|err| format!("upstream jwks invalid: {err}"))?;
    if jwks.signature_keys().next().is_none() {
        return Err("upstream jwks has no signature-capable keys".to_string());
    }
    Ok(jwks)
}

async fn fetch_upstream_jwks(
    client: &Client,
    jwks_uri: &str,
    allowed_domains: &[String],
) -> Result<JwkSet, String> {
    validate_upstream_outbound_url(jwks_uri, "upstream jwks_uri", allowed_domains)?;
    let response = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|_| "failed to fetch upstream jwks".to_string())?;
    if !response.status().is_success() {
        return Err(format!("upstream jwks returned {}", response.status()));
    }
    let body = crate::outbound_http::read_response_body_limited(response, UPSTREAM_MAX_BODY_BYTES)
        .await
        .map_err(|err| match err {
            crate::outbound_http::BoundedBodyError::TooLarge { .. } => {
                "upstream jwks response too large".to_string()
            }
            other => format!("failed to read upstream jwks: {other}"),
        })?;
    parse_upstream_jwks_body(&body)
}

pub(in crate::web) async fn fetch_upstream_jwks_cached(
    client: &Client,
    jwks_uri: &str,
    cache: &NonAuthoritativeMetadataCache<JwkSet>,
    allowed_domains: &[String],
) -> Result<JwkSet, String> {
    if let Some(cached) = cache.try_get(jwks_uri)? {
        return Ok(cached);
    }
    let jwks = fetch_upstream_jwks(client, jwks_uri, allowed_domains).await?;
    cache.try_insert(jwks_uri, jwks.clone())?;
    Ok(jwks)
}

pub(in crate::web) fn select_upstream_signing_key<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
) -> Result<&'a aegaeon_jose::jwk::Jwk, String> {
    let signing_keys: Vec<&aegaeon_jose::jwk::Jwk> = jwks.signature_keys().collect();
    if signing_keys.is_empty() {
        return Err("upstream jwks has no signature keys".to_string());
    }
    if let Some(kid) = kid {
        return signing_keys
            .into_iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .ok_or_else(|| "upstream jwks missing expected kid".to_string());
    }
    if signing_keys.len() == 1 {
        return Ok(signing_keys[0]);
    }
    Err("upstream jwks requires kid".to_string())
}
