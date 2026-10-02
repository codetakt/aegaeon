use super::super::UPSTREAM_MAX_BODY_BYTES;
use super::validate_upstream_outbound_url;
use aegaeon_jose::jwk::JwkSet;
use reqwest::Client;
use serde_json::Value;

use crate::upstream::NonAuthoritativeMetadataCache;
use crate::util;

pub(in crate::web) fn admit_upstream_jwks(value: &Value) -> Result<JwkSet, String> {
    crate::metadata::protocol_keys::validate_public_jwks(value).map_err(str::to_owned)?;
    let jwks = JwkSet::from_verification_value(value.clone())
        .map_err(|_| "upstream jwks invalid".to_string())?;
    jwks.ensure_unique_kid()
        .map_err(|_| "upstream jwks has duplicate kid".to_string())?;
    if jwks.verification_keys().next().is_none() {
        return Err("upstream jwks has no signature-capable keys".to_string());
    }
    Ok(jwks)
}

fn parse_upstream_jwks_original(body: &[u8]) -> Result<Value, String> {
    if body.len() > UPSTREAM_MAX_BODY_BYTES {
        return Err("upstream jwks response too large".to_string());
    }
    let value = util::deserialize_json_without_duplicate_object_keys::<Value>(body).map_err(
        |err| match err {
            util::JsonAdmissionError::DuplicateKey => {
                "upstream jwks response contains duplicate object keys".to_string()
            }
            _ => "upstream jwks response invalid".to_string(),
        },
    )?;
    admit_upstream_jwks(&value)?;
    Ok(value)
}

#[cfg(test)]
pub(in crate::web) fn parse_upstream_jwks_body(body: &[u8]) -> Result<JwkSet, String> {
    admit_upstream_jwks(&parse_upstream_jwks_original(body)?)
}

async fn fetch_upstream_jwks(
    client: &Client,
    jwks_uri: &str,
    allowed_domains: &[String],
) -> Result<Value, String> {
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
    parse_upstream_jwks_original(&body)
}

pub(in crate::web) async fn fetch_upstream_jwks_cached(
    client: &Client,
    jwks_uri: &str,
    cache: &NonAuthoritativeMetadataCache<Value>,
    allowed_domains: &[String],
) -> Result<JwkSet, String> {
    validate_upstream_outbound_url(jwks_uri, "upstream jwks_uri", allowed_domains)?;
    if let Some(cached) = cache.try_get(jwks_uri)? {
        return admit_upstream_jwks(&cached);
    }
    let original = fetch_upstream_jwks(client, jwks_uri, allowed_domains).await?;
    let jwks = admit_upstream_jwks(&original)?;
    cache.try_insert(jwks_uri, original)?;
    Ok(jwks)
}

pub(in crate::web) fn select_upstream_signing_key<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
) -> Result<&'a aegaeon_jose::jwk::Jwk, String> {
    crate::metadata::protocol_keys::validate_visible_public_jwks(jwks).map_err(str::to_owned)?;
    jwks.select_verification_key(kid)
        .map_err(|_| "upstream jwks has duplicate kid".to_string())?
        .ok_or_else(|| {
            if jwks.verification_keys().next().is_none() {
                "upstream jwks has no signature keys"
            } else if kid.is_some() {
                "upstream jwks missing expected kid"
            } else {
                "upstream jwks requires kid"
            }
            .to_string()
        })
}

#[cfg(test)]
mod protocol_key_tests;
