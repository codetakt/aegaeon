use super::super::upstream_id_token::AdmittedUpstreamIdTokenHeader;
use super::super::UPSTREAM_MAX_BODY_BYTES;
use super::validate_upstream_outbound_url;
use aegaeon_jose::jwk::{JwkSet, KeyMaterial};
use reqwest::Client;
use serde_json::Value;

use crate::upstream::{
    NonAuthoritativeMetadataCache, UpstreamJwksFetchCoordinator, JWKS_FETCH_COOLDOWN,
};
use crate::util;

pub(in crate::web) fn parse_upstream_jwks_body(body: &[u8]) -> Result<JwkSet, String> {
    if body.len() > UPSTREAM_MAX_BODY_BYTES {
        return Err("upstream jwks response too large".to_string());
    }
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
    let jwks = JwkSet::from_value(value).map_err(|_| "upstream jwks invalid".to_string())?;
    jwks.ensure_unique_kid()
        .map_err(|_| "upstream jwks invalid".to_string())?;
    if jwks.signature_keys().next().is_none() {
        return Err("upstream jwks has no signature-capable keys".to_string());
    }
    for key in jwks.keys() {
        let components = match &key.material {
            KeyMaterial::Rsa { n, e } => [n, e],
            KeyMaterial::Ec { x, y, .. } => [x, y],
        };
        if components
            .into_iter()
            .any(|value| !crate::upstream::canonical_base64url_segment(value))
        {
            return Err("upstream jwks key material encoding invalid".to_string());
        }
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
            _ => "failed to read upstream jwks".to_string(),
        })?;
    parse_upstream_jwks_body(&body)
}

pub(in crate::web) async fn fetch_upstream_jwks_cached<F, Fut>(
    client: &Client,
    jwks_uri: &str,
    cache: &NonAuthoritativeMetadataCache<JwkSet>,
    coordinator: &UpstreamJwksFetchCoordinator,
    header: &AdmittedUpstreamIdTokenHeader,
    allowed_domains: &[String],
    validate_fetched: F,
) -> Result<JwkSet, String>
where
    F: FnOnce(JwkSet) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    // Policy is checked even on cache hits, and the JWT never supplies a retrieval URL.
    validate_upstream_outbound_url(jwks_uri, "upstream jwks_uri", allowed_domains)?;
    if let Some(cached) = cache.try_get(jwks_uri)? {
        if !header.unfamiliar_kid(&cached) {
            return Ok(cached);
        }
    }
    let slot = coordinator.slot(jwks_uri, cache.max_entries())?;
    let (mut last_attempt, waited) = match slot.try_lock() {
        Ok(guard) => (guard, false),
        Err(_) => (slot.lock().await, true),
    };
    let cached = cache.try_get(jwks_uri)?;
    if let Some(cached) = cached.as_ref() {
        if !header.unfamiliar_kid(cached) {
            return Ok(cached.clone());
        }
    }
    let now = coordinator.now();
    if waited || last_attempt.is_some_and(|start| now.duration_since(start) < JWKS_FETCH_COOLDOWN) {
        // Never fetch twice for queued callers with distinct, attacker-selected kids.
        // An unexpired set remains non-authoritative; final verification still selects a key.
        return cached.ok_or_else(|| "upstream jwks retrieval cooling down".to_string());
    }
    // Retain this timestamp on error, timeout or cancellation. Dropping the mutex guard
    // releases in-flight ownership; the map keeps the cooldown until it is eligible to prune.
    *last_attempt = Some(now);
    let jwks = fetch_upstream_jwks(client, jwks_uri, allowed_domains).await?;
    // Keep the candidate private while the caller checks its Federation binding.
    // Rejection or cancellation preserves the previous set and its original TTL.
    // The URL slot remains locked so waiters cannot observe an unadmitted set.
    validate_fetched(jwks.clone()).await?;
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

#[cfg(test)]
mod tests;
