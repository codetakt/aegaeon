use super::super::upstream_id_token::AdmittedUpstreamIdTokenHeader;
use super::super::UPSTREAM_MAX_BODY_BYTES;
use super::validate_upstream_outbound_url;
use aegaeon_jose::jwk::JwkSet;
use reqwest::Client;
use serde_json::Value;
use std::sync::{Arc, OnceLock};

use crate::upstream::{
    NonAuthoritativeMetadataCache, UpstreamJwksFetchCoordinator, JWKS_FETCH_COOLDOWN,
};
use crate::util;

/// Immutable original metadata and its lazily admitted verification view.
/// Cache clones share admission; returned JWK sets remain independent copies.
#[derive(Clone, Debug)]
pub struct CachedUpstreamJwks {
    original: Arc<Value>,
    admitted: Arc<OnceLock<Result<JwkSet, String>>>,
}

impl From<Value> for CachedUpstreamJwks {
    fn from(original: Value) -> Self {
        Self {
            original: Arc::new(original),
            admitted: Arc::new(OnceLock::new()),
        }
    }
}

impl CachedUpstreamJwks {
    pub(in crate::web) fn verification_view(&self) -> Result<JwkSet, String> {
        // Recheck the raw public profile on every reuse without redecoding every
        // RSA/EC member. Selection still validates the current selected material.
        crate::metadata::protocol_keys::validate_public_jwks(&self.original)
            .map_err(str::to_owned)?;
        self.admitted
            .get_or_init(|| admit_upstream_jwks(&self.original))
            .clone()
    }

    #[cfg(test)]
    pub(in crate::web) fn original(&self) -> &Value {
        &self.original
    }
}

#[cfg(test)]
thread_local! {
    static JWKS_ADMISSIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(in crate::web) fn admit_upstream_jwks(value: &Value) -> Result<JwkSet, String> {
    #[cfg(test)]
    JWKS_ADMISSIONS.with(|count| count.set(count.get() + 1));
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

fn parse_upstream_jwks_original(body: &[u8]) -> Result<CachedUpstreamJwks, String> {
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
    let cached = CachedUpstreamJwks::from(value);
    cached.verification_view()?;
    Ok(cached)
}

#[cfg(test)]
pub(in crate::web) fn parse_upstream_jwks_body(body: &[u8]) -> Result<JwkSet, String> {
    parse_upstream_jwks_original(body)?.verification_view()
}

async fn fetch_upstream_jwks(
    client: &Client,
    jwks_uri: &str,
    allowed_domains: &[String],
) -> Result<CachedUpstreamJwks, String> {
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
    parse_upstream_jwks_original(&body)
}

pub(in crate::web) async fn fetch_upstream_jwks_cached<F, Fut>(
    client: &Client,
    jwks_uri: &str,
    cache: &NonAuthoritativeMetadataCache<CachedUpstreamJwks>,
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
    if let Some(original) = cache.try_get(jwks_uri)? {
        let cached = original.verification_view()?;
        if !header.unfamiliar_kid(&cached) {
            return Ok(cached);
        }
    }
    let slot = coordinator.slot(jwks_uri, cache.max_entries())?;
    let (mut last_attempt, waited) = match slot.try_lock() {
        Ok(guard) => (guard, false),
        Err(_) => (slot.lock().await, true),
    };
    let cached = cache
        .try_get(jwks_uri)?
        .as_ref()
        .map(CachedUpstreamJwks::verification_view)
        .transpose()?;
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
    let original = fetch_upstream_jwks(client, jwks_uri, allowed_domains).await?;
    let jwks = original.verification_view()?;
    // Keep the candidate private while the caller checks its Federation binding.
    // Rejection or cancellation preserves the previous set and its original TTL.
    // The URL slot remains locked so waiters cannot observe an unadmitted set.
    validate_fetched(jwks.clone()).await?;
    cache.try_insert(jwks_uri, original)?;
    Ok(jwks)
}

pub(in crate::web) fn select_upstream_signing_key<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
) -> Result<&'a aegaeon_jose::jwk::Jwk, String> {
    crate::metadata::protocol_keys::validate_visible_public_jwks(jwks).map_err(str::to_owned)?;
    jwks.select_verification_key(kid)
        .map_err(|_| "upstream jwks has duplicate kids".to_string())?
        .ok_or_else(|| "upstream jwks has no unique eligible key".to_string())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod protocol_key_tests;
